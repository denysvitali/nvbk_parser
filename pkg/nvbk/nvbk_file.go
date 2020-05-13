package nvbk

type NVBKHeader struct {
	Total     int
	Valid     int
	Verify    bool
	BuildTime string
}

type NVBKFile struct {
	Header NVBKHeader
}
