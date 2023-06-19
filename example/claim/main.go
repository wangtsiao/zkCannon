package main

import (
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"io"
	"os"
)

type Key interface {
	// PreimageKey changes the Key commitment into a
	// 32-byte type-prefixed preimage key.
	PreimageKey() [32]byte
}

type Oracle interface {
	// Get the full pre-image of a given pre-image key.
	// This returns no error: the client state-transition
	// is invalid if there is any missing pre-image data.
	Get(key Key) []byte
}

// KeyType is the key-type of a pre-image, used to prefix the pre-image key with.
type KeyType byte

const (
	// The zero key type is illegal to use, ensuring all keys are non-zero.
	_ KeyType = 0
	// LocalKeyType is for input-type pre-images, specific to the local program instance.
	LocalKeyType KeyType = 1
	// Keccak256KeyType is for keccak256 pre-images, for any global shared pre-images.
	Keccak256KeyType KeyType = 2
)

// LocalIndexKey is a key local to the program, indexing a special program input.
type LocalIndexKey uint64

func (k LocalIndexKey) PreimageKey() (out [32]byte) {
	out[0] = byte(LocalKeyType)
	binary.BigEndian.PutUint64(out[24:], uint64(k))
	return
}

// Keccak256Key wraps a keccak256 hash to use it as a typed pre-image key.
type Keccak256Key [32]byte

func (k Keccak256Key) PreimageKey() (out [32]byte) {
	out = k                         // copy the keccak hash
	out[0] = byte(Keccak256KeyType) // apply prefix
	return
}

func (k Keccak256Key) String() string {
	return "0x" + hex.EncodeToString(k[:])
}

func (k Keccak256Key) TerminalString() string {
	return "0x" + hex.EncodeToString(k[:])
}

// Hint is an interface to enable any program type to function as a hint,
// when passed to the Hinter interface, returning a string representation
// of what data the host should prepare pre-images for.
type Hint interface {
	Hint() string
}

// Hinter is an interface to write hints to the host.
// This may be implemented as a no-op or logging hinter
// if the program is executing in a read-only environment
// where the host is expected to have all pre-images ready.
type Hinter interface {
	Hint(v Hint)
}

// OracleClient implements the Oracle by writing the pre-image key to the given stream,
// and reading back a length-prefixed value.
type OracleClient struct {
	rw io.ReadWriter
}

func NewOracleClient(rw io.ReadWriter) *OracleClient {
	return &OracleClient{rw: rw}
}

var _ Oracle = (*OracleClient)(nil)

func (o *OracleClient) Get(key Key) []byte {
	h := key.PreimageKey()
	if _, err := o.rw.Write(h[:]); err != nil {
		panic(fmt.Errorf("failed to write key %s (%T) to pre-image oracle: %w", key, key, err))
	}

	var length uint64
	if err := binary.Read(o.rw, binary.BigEndian, &length); err != nil {
		panic(fmt.Errorf("failed to read pre-image length of key %s (%T) from pre-image oracle: %w", key, key, err))
	}
	payload := make([]byte, length)
	if _, err := io.ReadFull(o.rw, payload); err != nil {
		panic(fmt.Errorf("failed to read pre-image payload (length %d) of key %s (%T) from pre-image oracle: %w", length, key, key, err))
	}

	return payload
}

// HintWriter writes hints to an io.Writer (e.g. a special file descriptor, or a debug log),
// for a pre-image oracle service to prepare specific pre-images.
type HintWriter struct {
	rw io.ReadWriter
}

var _ Hinter = (*HintWriter)(nil)

func NewHintWriter(rw io.ReadWriter) *HintWriter {
	return &HintWriter{rw: rw}
}

func (hw *HintWriter) Hint(v Hint) {
	hint := v.Hint()
	var hintBytes []byte
	hintBytes = binary.BigEndian.AppendUint32(hintBytes, uint32(len(hint)))
	hintBytes = append(hintBytes, []byte(hint)...)
	_, err := hw.rw.Write(hintBytes)
	if err != nil {
		panic(fmt.Errorf("failed to write pre-image hint: %w", err))
	}
	_, err = hw.rw.Read([]byte{0})
	if err != nil {
		panic(fmt.Errorf("failed to read pre-image hint ack: %w", err))
	}
}

type ReadWritePair struct {
	r *os.File
	w *os.File
}

// NewReadWritePair creates a new FileChannel that uses the given files
func NewReadWritePair(r *os.File, w *os.File) *ReadWritePair {
	return &ReadWritePair{r: r, w: w}
}

func (rw *ReadWritePair) Read(p []byte) (int, error) {
	return rw.r.Read(p)
}

func (rw *ReadWritePair) Write(p []byte) (int, error) {
	return rw.w.Write(p)
}

func (rw *ReadWritePair) Reader() *os.File {
	return rw.r
}

func (rw *ReadWritePair) Writer() *os.File {
	return rw.w
}

func (rw *ReadWritePair) Close() error {
	if err := rw.r.Close(); err != nil {
		return err
	}
	return rw.w.Close()
}

const (
	HClientRFd = 3
	HClientWFd = 4
	PClientRFd = 5
	PClientWFd = 6
)

func ClientHinterChannel() *ReadWritePair {
	r := os.NewFile(HClientRFd, "preimage-hint-read")
	w := os.NewFile(HClientWFd, "preimage-hint-write")
	return NewReadWritePair(r, w)
}

// ClientPreimageChannel returns a FileChannel for the preimage oracle in a detached context
func ClientPreimageChannel() *ReadWritePair {
	r := os.NewFile(PClientRFd, "preimage-oracle-read")
	w := os.NewFile(PClientWFd, "preimage-oracle-write")
	return NewReadWritePair(r, w)
}

type rawHint string

func (rh rawHint) Hint() string {
	return string(rh)
}

func main() {
	_, _ = os.Stderr.Write([]byte("started!"))

	po := NewOracleClient(ClientPreimageChannel())
	hinter := NewHintWriter(ClientHinterChannel())

	preHash := *(*[32]byte)(po.Get(LocalIndexKey(0)))
	diffHash := *(*[32]byte)(po.Get(LocalIndexKey(1)))
	claimData := *(*[8]byte)(po.Get(LocalIndexKey(2)))

	// Hints are used to indicate which things the program will access,
	// so the server can be prepared to serve the corresponding pre-images.
	hinter.Hint(rawHint(fmt.Sprintf("fetch-state %x", preHash)))
	pre := po.Get(Keccak256Key(preHash))

	// Multiple pre-images may be fetched based on a hint.
	// E.g. when we need all values of a merkle-tree.
	hinter.Hint(rawHint(fmt.Sprintf("fetch-diff %x", diffHash)))
	diff := po.Get(Keccak256Key(diffHash))
	diffPartA := po.Get(Keccak256Key(*(*[32]byte)(diff[:32])))
	diffPartB := po.Get(Keccak256Key(*(*[32]byte)(diff[32:])))

	// Example state-transition function: s' = s*a + b
	s := binary.BigEndian.Uint64(pre)
	a := binary.BigEndian.Uint64(diffPartA)
	b := binary.BigEndian.Uint64(diffPartB)
	fmt.Printf("computing %d * %d + %d\n", s, a, b)
	sOut := s*a + b

	sClaim := binary.BigEndian.Uint64(claimData[:])
	if sOut != sClaim {
		fmt.Printf("claim %d is bad! Correct result is %d\n", sOut, sClaim)
		os.Exit(1)
	} else {
		fmt.Printf("claim %d is good!\n", sOut)
		os.Exit(0)
	}
}
