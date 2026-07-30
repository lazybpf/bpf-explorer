package inspector

// BTF-aware value formatting, ported verbatim from tools/lazyebpf/btfdump.go so
// the web UI decodes map keys/values the way `bpftool map dump` does. The only
// change is the package name; the algorithms are unchanged.

import (
	"fmt"
	"math"
	"runtime"
	"strconv"
	"strings"
	"syscall"
	"unsafe"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/btf"
	"golang.org/x/sys/unix"
)

// bpfMapInfo mirrors the kernel's struct bpf_map_info. cilium/ebpf's public
// MapInfo does not expose btf_key_type_id / btf_value_type_id, which we need to
// decode a map's contents, so we query it ourselves.
type bpfMapInfo struct {
	Type                  uint32
	ID                    uint32
	KeySize               uint32
	ValueSize             uint32
	MaxEntries            uint32
	MapFlags              uint32
	Name                  [16]byte
	Ifindex               uint32
	BtfVmlinuxValueTypeID uint32
	NetnsDev              uint64
	NetnsIno              uint64
	BtfID                 uint32
	BtfKeyTypeID          uint32
	BtfValueTypeID        uint32
	BtfVmlinuxID          uint32
	MapExtra              uint64
}

func queryMapInfo(fd int) (*bpfMapInfo, error) {
	var info bpfMapInfo
	attr := struct {
		fd      uint32
		infoLen uint32
		info    uint64
	}{
		fd:      uint32(fd),
		infoLen: uint32(unsafe.Sizeof(info)),
		info:    uint64(uintptr(unsafe.Pointer(&info))),
	}
	_, _, errno := syscall.Syscall(uintptr(unix.SYS_BPF),
		uintptr(unix.BPF_OBJ_GET_INFO_BY_FD),
		uintptr(unsafe.Pointer(&attr)),
		unsafe.Sizeof(attr))
	runtime.KeepAlive(&info)
	if errno != 0 {
		return nil, errno
	}
	return &info, nil
}

func mapBTFTypes(m *ebpf.Map) (keyType, valueType btf.Type) {
	info, err := queryMapInfo(m.FD())
	if err != nil || info.BtfID == 0 {
		return nil, nil
	}
	h, err := btf.NewHandleFromID(btf.ID(info.BtfID))
	if err != nil {
		return nil, nil
	}
	defer h.Close()
	spec, err := h.Spec(nil)
	if err != nil {
		return nil, nil
	}
	if info.BtfKeyTypeID != 0 {
		keyType, _ = spec.TypeByID(btf.TypeID(info.BtfKeyTypeID))
	}
	if info.BtfValueTypeID != 0 {
		valueType, _ = spec.TypeByID(btf.TypeID(info.BtfValueTypeID))
	}
	return keyType, valueType
}

func formatBTF(typ btf.Type, data []byte) string {
	if typ == nil {
		return hexBytes(data)
	}
	return formatValue(typ, data)
}

func formatValue(typ btf.Type, data []byte) string {
	switch t := btf.UnderlyingType(typ).(type) {
	case *btf.Int:
		return formatInt(t, data)
	case *btf.Enum:
		return formatEnum(t, data)
	case *btf.Pointer:
		return fmt.Sprintf("0x%x", readUint(data, 8))
	case *btf.Float:
		return formatFloat(t, data)
	case *btf.Struct:
		return formatFields(t.Members, data)
	case *btf.Union:
		return formatFields(t.Members, data)
	case *btf.Array:
		return formatArray(t, data)
	default:
		return hexBytes(data)
	}
}

func formatInt(t *btf.Int, data []byte) string {
	n := int(t.Size)
	if n == 0 || n > 8 || n > len(data) {
		return hexBytes(data)
	}
	u := readUint(data, n)
	switch t.Encoding {
	case btf.Bool:
		return strconv.FormatBool(u != 0)
	case btf.Char:
		if n == 1 {
			if b := byte(u); b >= 0x20 && b < 0x7f {
				return fmt.Sprintf("'%c'", b)
			}
			return strconv.Itoa(int(u))
		}
	case btf.Signed:
		return strconv.FormatInt(signExtend(u, n), 10)
	}
	return strconv.FormatUint(u, 10)
}

func formatEnum(t *btf.Enum, data []byte) string {
	u := readUint(data, int(t.Size))
	for _, v := range t.Values {
		if v.Value == u {
			return v.Name
		}
	}
	return strconv.FormatUint(u, 10)
}

func formatFloat(t *btf.Float, data []byte) string {
	switch t.Size {
	case 4:
		return strconv.FormatFloat(float64(math.Float32frombits(uint32(readUint(data, 4)))), 'g', -1, 32)
	case 8:
		return strconv.FormatFloat(math.Float64frombits(readUint(data, 8)), 'g', -1, 64)
	default:
		return hexBytes(data)
	}
}

func formatArray(t *btf.Array, data []byte) string {
	elem := btf.UnderlyingType(t.Type)
	elemSize, err := btf.Sizeof(elem)
	if err != nil || elemSize <= 0 {
		return hexBytes(data)
	}
	// Render char arrays as quoted C strings, like bpftool does.
	if it, ok := elem.(*btf.Int); ok && it.Size == 1 && it.Encoding == btf.Char {
		return strconv.Quote(cString(data))
	}
	parts := make([]string, 0, t.Nelems)
	for i := 0; i < int(t.Nelems); i++ {
		off := i * elemSize
		if off+elemSize > len(data) {
			break
		}
		parts = append(parts, formatValue(t.Type, data[off:off+elemSize]))
	}
	return "[" + strings.Join(parts, ", ") + "]"
}

func formatFields(members []btf.Member, data []byte) string {
	parts := make([]string, 0, len(members))
	for _, mem := range members {
		name := mem.Name
		if name == "" {
			name = "_"
		}
		var val string
		switch {
		case mem.BitfieldSize > 0:
			val = strconv.FormatUint(readBitfield(data, uint(mem.Offset), uint(mem.BitfieldSize)), 10)
		default:
			byteOff := int(mem.Offset) / 8
			size, err := btf.Sizeof(btf.UnderlyingType(mem.Type))
			if err != nil || byteOff > len(data) {
				val = "?"
				break
			}
			end := byteOff + size
			if end > len(data) {
				end = len(data)
			}
			val = formatValue(mem.Type, data[byteOff:end])
		}
		parts = append(parts, name+"="+val)
	}
	return "{ " + strings.Join(parts, ", ") + " }"
}

// readUint reads up to n (max 8) little-endian bytes into a uint64.
func readUint(b []byte, n int) uint64 {
	if n > 8 {
		n = 8
	}
	var v uint64
	for i := 0; i < n && i < len(b); i++ {
		v |= uint64(b[i]) << (8 * i)
	}
	return v
}

// signExtend interprets the low n*8 bits of u as a two's-complement integer.
func signExtend(u uint64, n int) int64 {
	bits := uint(n * 8)
	if bits >= 64 {
		return int64(u)
	}
	shift := 64 - bits
	return int64(u<<shift) >> shift
}

// readBitfield extracts bitWidth bits starting at bitOff (LSB-first).
func readBitfield(data []byte, bitOff, bitWidth uint) uint64 {
	var v uint64
	for i := uint(0); i < bitWidth && i < 64; i++ {
		bit := bitOff + i
		if int(bit/8) >= len(data) {
			break
		}
		if data[bit/8]&(1<<(bit%8)) != 0 {
			v |= 1 << i
		}
	}
	return v
}

// cString returns the bytes up to the first NUL as a string.
func cString(b []byte) string {
	if i := strings.IndexByte(string(b), 0); i >= 0 {
		return string(b[:i])
	}
	return string(b)
}

func hexBytes(b []byte) string {
	if len(b) == 0 {
		return "<empty>"
	}
	parts := make([]string, len(b))
	for i, x := range b {
		parts[i] = fmt.Sprintf("%02x", x)
	}
	return strings.Join(parts, " ")
}
