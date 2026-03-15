package main

import (
	"bytes"
	"fmt"
	"strconv"
	"sync"
	"time"

	"github.com/gdamore/tcell/v2"
	"github.com/rivo/tview"
)

const maxCaptureSize = 1 << 20 // 1 MB per direction

type Connection struct {
	ID             int
	Target         string
	ClientAddr     string
	StartTime      time.Time
	Status         string // "ACTIVE", "CLOSED", "FAILED"
	TLSIntercepted bool
	mu             sync.Mutex
	ClientToServer bytes.Buffer
	ServerToClient bytes.Buffer
	parsedReq      *ParsedHTTP
	parsedResp     *ParsedHTTP
	lastReqLen     int
	lastRespLen    int
}

func (c *Connection) Request() *ParsedHTTP {
	c.mu.Lock()
	defer c.mu.Unlock()
	curLen := c.ClientToServer.Len()
	if c.parsedReq == nil || curLen != c.lastReqLen {
		c.parsedReq = ParseHTTPRequest(c.ClientToServer.Bytes())
		c.lastReqLen = curLen
	}
	return c.parsedReq
}

func (c *Connection) Response() *ParsedHTTP {
	c.mu.Lock()
	defer c.mu.Unlock()
	curLen := c.ServerToClient.Len()
	if c.parsedResp == nil || curLen != c.lastRespLen {
		c.parsedResp = ParseHTTPResponse(c.ServerToClient.Bytes())
		c.lastRespLen = curLen
	}
	return c.parsedResp
}

func (c *Connection) RequestBytes() []byte {
	c.mu.Lock()
	defer c.mu.Unlock()
	b := make([]byte, c.ClientToServer.Len())
	copy(b, c.ClientToServer.Bytes())
	return b
}

func (c *Connection) ResponseBytes() []byte {
	c.mu.Lock()
	defer c.mu.Unlock()
	b := make([]byte, c.ServerToClient.Len())
	copy(b, c.ServerToClient.Bytes())
	return b
}

type ConnectionStore struct {
	mu     sync.Mutex
	conns  []*Connection
	nextID int
}

func NewConnectionStore() *ConnectionStore {
	return &ConnectionStore{nextID: 1}
}

func (s *ConnectionStore) Add(target, clientAddr string) *Connection {
	s.mu.Lock()
	defer s.mu.Unlock()
	c := &Connection{
		ID:         s.nextID,
		Target:     target,
		ClientAddr: clientAddr,
		StartTime:  time.Now(),
		Status:     "ACTIVE",
	}
	s.nextID++
	s.conns = append(s.conns, c)
	return c
}

func (s *ConnectionStore) All() []*Connection {
	s.mu.Lock()
	defer s.mu.Unlock()
	result := make([]*Connection, len(s.conns))
	copy(result, s.conns)
	return result
}

// viewTab: which payload to show
type viewTab int

const (
	tabRequest viewTab = iota
	tabResponse
)

// formatTab: how to render the payload
type formatTab int

const (
	fmtRaw formatTab = iota
	fmtHeaders
	fmtHex
)

type UI struct {
	App         *tview.Application
	Store       *ConnectionStore
	Interceptor *Interceptor

	// Layout pieces
	hostList    *tview.List
	reqTable    *tview.Table
	tabBar      *tview.TextView
	detail      *tview.TextView
	editor      *tview.TextArea
	statusBar   *tview.TextView
	bottomPane  *tview.Flex

	// State
	viewMode    viewTab
	fmtMode     formatTab
	selConn     int // index into filtered list
	hosts       []string
	selHost     string // "" means all
	filtered    []*Connection
	db          *DB
	listenAddr  string
	editing     bool
	currentIntercept *InterceptRequest

	refreshMu   sync.Mutex
	lastRefresh time.Time
}

func NewUI(store *ConnectionStore, listenAddr string, db *DB, interceptor *Interceptor) *UI {
	app := tview.NewApplication()

	hostList := tview.NewList()
	hostList.SetBorder(true).SetTitle(" Hosts ")
	hostList.ShowSecondaryText(false)
	hostList.SetHighlightFullLine(true)

	reqTable := tview.NewTable()
	reqTable.SetBorder(true).SetTitle(" HTTP History ")
	reqTable.SetSelectable(true, false)
	reqTable.SetFixed(1, 0) // header row

	tabBar := tview.NewTextView()
	tabBar.SetDynamicColors(true)
	tabBar.SetTextAlign(tview.AlignLeft)

	detail := tview.NewTextView()
	detail.SetBorder(true)
	detail.SetScrollable(true)
	detail.SetWrap(false)
	detail.SetDynamicColors(false)

	editor := tview.NewTextArea()
	editor.SetBorder(true)
	editor.SetTitle(" Edit Request | Ctrl+F: forward | Ctrl+X: drop ")

	statusBar := tview.NewTextView()
	statusBar.SetDynamicColors(true)

	ui := &UI{
		App:         app,
		Store:       store,
		Interceptor: interceptor,
		hostList:    hostList,
		reqTable:    reqTable,
		tabBar:      tabBar,
		detail:      detail,
		editor:      editor,
		statusBar:   statusBar,
		viewMode:    tabRequest,
		fmtMode:     fmtRaw,
		db:          db,
		listenAddr:  listenAddr,
	}

	// Table header
	ui.setTableHeaders()

	// Host selection
	hostList.SetChangedFunc(func(index int, mainText, secondaryText string, shortcut rune) {
		if index == 0 {
			ui.selHost = ""
		} else if index-1 < len(ui.hosts) {
			ui.selHost = ui.hosts[index-1]
		}
		ui.rebuildTable()
	})

	// Table row selection
	reqTable.SetSelectionChangedFunc(func(row, col int) {
		if row <= 0 || row-1 >= len(ui.filtered) {
			return
		}
		ui.selConn = row - 1
		ui.updateDetail()
	})

	// Layout: top = hosts + table, bottom = tabs + detail/editor
	topPane := tview.NewFlex().SetDirection(tview.FlexColumn).
		AddItem(hostList, 30, 0, true).
		AddItem(reqTable, 0, 1, false)

	bottomPane := tview.NewFlex().SetDirection(tview.FlexRow).
		AddItem(tabBar, 1, 0, false).
		AddItem(detail, 0, 1, false)
	ui.bottomPane = bottomPane

	mainLayout := tview.NewFlex().SetDirection(tview.FlexRow).
		AddItem(topPane, 0, 1, true).
		AddItem(bottomPane, 0, 1, false).
		AddItem(statusBar, 1, 0, false)

	app.SetRoot(mainLayout, true)

	// Focus cycling: hostList -> reqTable -> detail
	focusOrder := []tview.Primitive{hostList, reqTable, detail}
	focusIdx := 0

	app.SetInputCapture(func(event *tcell.EventKey) *tcell.EventKey {
		// When editing an intercepted request, only handle editor keys
		if ui.editing {
			switch event.Key() {
			case tcell.KeyCtrlF:
				ui.forwardIntercept()
				return nil
			case tcell.KeyCtrlX:
				ui.dropIntercept()
				return nil
			}
			// Let all other keys pass through to the TextArea
			return event
		}

		switch event.Key() {
		case tcell.KeyTab:
			focusIdx = (focusIdx + 1) % len(focusOrder)
			app.SetFocus(focusOrder[focusIdx])
			return nil
		case tcell.KeyBacktab:
			focusIdx = (focusIdx - 1 + len(focusOrder)) % len(focusOrder)
			app.SetFocus(focusOrder[focusIdx])
			return nil
		case tcell.KeyRune:
			switch event.Rune() {
			case 'q':
				app.Stop()
				return nil
			case '1':
				ui.viewMode = tabRequest
				ui.updateTabBar()
				ui.updateDetail()
				return nil
			case '2':
				ui.viewMode = tabResponse
				ui.updateTabBar()
				ui.updateDetail()
				return nil
			case 'r':
				ui.fmtMode = fmtRaw
				ui.updateTabBar()
				ui.updateDetail()
				return nil
			case 'h':
				ui.fmtMode = fmtHeaders
				ui.updateTabBar()
				ui.updateDetail()
				return nil
			case 'x':
				ui.fmtMode = fmtHex
				ui.updateTabBar()
				ui.updateDetail()
				return nil
			case 'd':
				if ui.db != nil {
					ui.db.Toggle()
					ui.updateStatusBar()
				}
				return nil
			case 'S':
				if ui.db != nil {
					saved, err := ui.db.SaveAllConnections(ui.Store)
					if err != nil {
						ui.statusBar.SetText(fmt.Sprintf(" [red]DB error: %v", err))
					} else {
						ui.statusBar.SetText(fmt.Sprintf(" [green]Saved %d connections to %s", saved, ui.db.Path()))
					}
				}
				return nil
			case 'i':
				enabled := ui.Interceptor.Toggle()
				_ = enabled
				ui.updateStatusBar()
				return nil
			}
		}
		return event
	})

	// Start goroutine that watches for pending intercept requests
	go ui.watchIntercepts()

	ui.updateTabBar()
	ui.updateStatusBar()

	return ui
}

// watchIntercepts listens for incoming intercept requests and shows the editor.
func (ui *UI) watchIntercepts() {
	for req := range ui.Interceptor.Pending() {
		ui.App.QueueUpdateDraw(func() {
			ui.showEditor(req)
		})
	}
}

// showEditor swaps the detail view for the editable text area.
func (ui *UI) showEditor(req *InterceptRequest) {
	ui.editing = true
	ui.currentIntercept = req

	// Show the raw request data in the editor
	ui.editor.SetText(string(req.Data), true)
	connLabel := fmt.Sprintf(" Edit Request #%d -> %s | Ctrl+F: forward | Ctrl+X: drop ", req.Conn.ID, req.Conn.Target)
	ui.editor.SetTitle(connLabel)

	// Swap detail for editor in bottom pane
	ui.bottomPane.RemoveItem(ui.detail)
	ui.bottomPane.AddItem(ui.editor, 0, 1, true)
	ui.App.SetFocus(ui.editor)

	ui.updateTabBar()
	ui.updateStatusBar()
}

// hideEditor swaps the editor back to the detail view.
func (ui *UI) hideEditor() {
	ui.editing = false
	ui.currentIntercept = nil

	ui.bottomPane.RemoveItem(ui.editor)
	ui.bottomPane.AddItem(ui.detail, 0, 1, false)
	ui.App.SetFocus(ui.reqTable)

	ui.updateTabBar()
	ui.updateStatusBar()
}

// forwardIntercept sends the (possibly edited) data to the proxy and closes the editor.
func (ui *UI) forwardIntercept() {
	if ui.currentIntercept == nil {
		return
	}

	editedText := ui.editor.GetText()
	ui.currentIntercept.Result <- InterceptResult{
		Data:    []byte(editedText),
		Forward: true,
	}
	ui.hideEditor()
}

// dropIntercept drops the connection and closes the editor.
func (ui *UI) dropIntercept() {
	if ui.currentIntercept == nil {
		return
	}

	ui.currentIntercept.Result <- InterceptResult{
		Forward: false,
	}
	ui.hideEditor()
}

func (ui *UI) setTableHeaders() {
	headers := []string{"#", "Host", "Method", "URL", "Status", "Length", "MIME", "TLS"}
	for i, h := range headers {
		cell := tview.NewTableCell(h).
			SetSelectable(false).
			SetTextColor(tcell.ColorYellow).
			SetAttributes(tcell.AttrBold)
		if i == 3 { // URL column gets more space
			cell.SetExpansion(2)
		} else {
			cell.SetExpansion(1)
		}
		ui.reqTable.SetCell(0, i, cell)
	}
}

func (ui *UI) updateStatusBar() {
	dbStatus := ""
	if ui.db != nil {
		if ui.db.IsEnabled() {
			dbStatus = fmt.Sprintf("  [green]DB: ON[white] (%s)", ui.db.Path())
		} else {
			dbStatus = "  [red]DB: OFF[white]"
		}
	}

	interceptStatus := " [red]OFF[white]"
	if ui.Interceptor.IsEnabled() {
		interceptStatus = " [green]ON[white]"
	}
	if ui.editing {
		interceptStatus += fmt.Sprintf(" [yellow](editing #%d)[white]", ui.currentIntercept.Conn.ID)
	}
	qLen := ui.Interceptor.QueueLen()
	if qLen > 0 {
		interceptStatus += fmt.Sprintf(" [yellow](%d queued)[white]", qLen)
	}

	ui.statusBar.SetText(fmt.Sprintf(
		" [yellow]Listening:[white] %s%s  [yellow]Intercept:[white]%s  [yellow]i:[white] toggle  [yellow]1/2:[white] Req/Resp  [yellow]r/h/x:[white] Raw/Headers/Hex  [yellow]d:[white] DB  [yellow]q:[white] quit",
		ui.listenAddr, dbStatus, interceptStatus,
	))
}

func (ui *UI) updateTabBar() {
	reqLabel := "  Request  "
	respLabel := "  Response  "
	rawLabel := "  Raw  "
	headersLabel := "  Headers  "
	hexLabel := "  Hex  "

	if ui.editing {
		ui.tabBar.SetText(" [black:red] INTERCEPTED [-:-]   Ctrl+F: forward edited request   Ctrl+X: drop connection")
		return
	}

	if ui.viewMode == tabRequest {
		reqLabel = " [black:yellow] Request [-:-] "
	} else {
		respLabel = " [black:yellow] Response [-:-] "
	}

	switch ui.fmtMode {
	case fmtRaw:
		rawLabel = " [black:green] Raw [-:-] "
	case fmtHeaders:
		headersLabel = " [black:green] Headers [-:-] "
	case fmtHex:
		hexLabel = " [black:green] Hex [-:-] "
	}

	ui.tabBar.SetText(fmt.Sprintf(" %s%s    %s%s%s", reqLabel, respLabel, rawLabel, headersLabel, hexLabel))
}

func (ui *UI) updateDetail() {
	if ui.editing {
		return
	}
	if ui.selConn < 0 || ui.selConn >= len(ui.filtered) {
		ui.detail.SetText("")
		return
	}

	conn := ui.filtered[ui.selConn]

	var data []byte
	var parsed *ParsedHTTP

	if ui.viewMode == tabRequest {
		data = conn.RequestBytes()
		parsed = conn.Request()
		ui.detail.SetTitle(" Request ")
	} else {
		data = conn.ResponseBytes()
		parsed = conn.Response()
		ui.detail.SetTitle(" Response ")
	}

	var text string
	switch ui.fmtMode {
	case fmtRaw:
		text = formatRaw(data)
	case fmtHeaders:
		text = formatHeaders(parsed)
	case fmtHex:
		text = formatHex(data)
	}

	ui.detail.SetText(text)
	ui.detail.ScrollToBeginning()
}

func (ui *UI) rebuildTable() {
	conns := ui.Store.All()

	// Filter by host
	ui.filtered = nil
	for _, c := range conns {
		if ui.selHost == "" || hostFromTarget(c.Target) == ui.selHost {
			ui.filtered = append(ui.filtered, c)
		}
	}

	// Clear table rows (keep header)
	rowCount := ui.reqTable.GetRowCount()
	for r := rowCount - 1; r >= 1; r-- {
		ui.reqTable.RemoveRow(r)
	}

	for i, c := range ui.filtered {
		row := i + 1
		req := c.Request()
		resp := c.Response()

		method := "-"
		url := c.Target
		status := ""
		length := ""
		mime := ""

		if req.IsHTTP {
			method = req.Method
			url = req.URL
		}
		if resp.IsHTTP {
			status = strconv.Itoa(resp.StatusCode)
			cl := resp.Header("Content-Length")
			if cl != "" {
				length = cl
			} else {
				c.mu.Lock()
				length = strconv.Itoa(c.ServerToClient.Len())
				c.mu.Unlock()
			}
			mime = resp.ContentType()
		}

		tlsStr := ""
		if c.TLSIntercepted {
			tlsStr = "yes"
		}

		statusColor := tcell.ColorWhite
		if resp.IsHTTP {
			switch {
			case resp.StatusCode >= 200 && resp.StatusCode < 300:
				statusColor = tcell.ColorGreen
			case resp.StatusCode >= 300 && resp.StatusCode < 400:
				statusColor = tcell.ColorYellow
			case resp.StatusCode >= 400:
				statusColor = tcell.ColorRed
			}
		}

		connColor := tcell.ColorWhite
		c.mu.Lock()
		st := c.Status
		c.mu.Unlock()
		if st == "FAILED" {
			connColor = tcell.ColorRed
		}

		ui.reqTable.SetCell(row, 0, tview.NewTableCell(strconv.Itoa(c.ID)).SetTextColor(connColor).SetExpansion(1))
		ui.reqTable.SetCell(row, 1, tview.NewTableCell(hostFromTarget(c.Target)).SetTextColor(connColor).SetExpansion(1))
		ui.reqTable.SetCell(row, 2, tview.NewTableCell(method).SetTextColor(tcell.ColorAqua).SetExpansion(1))
		ui.reqTable.SetCell(row, 3, tview.NewTableCell(url).SetExpansion(2))
		ui.reqTable.SetCell(row, 4, tview.NewTableCell(status).SetTextColor(statusColor).SetExpansion(1))
		ui.reqTable.SetCell(row, 5, tview.NewTableCell(length).SetExpansion(1))
		ui.reqTable.SetCell(row, 6, tview.NewTableCell(mime).SetExpansion(1))
		ui.reqTable.SetCell(row, 7, tview.NewTableCell(tlsStr).SetExpansion(1))
	}
}

func (ui *UI) RefreshList() {
	// Throttle to avoid flooding
	ui.refreshMu.Lock()
	if time.Since(ui.lastRefresh) < 100*time.Millisecond {
		ui.refreshMu.Unlock()
		return
	}
	ui.lastRefresh = time.Now()
	ui.refreshMu.Unlock()

	ui.App.QueueUpdateDraw(func() {
		// Rebuild host list
		conns := ui.Store.All()
		hostSet := make(map[string]bool)
		for _, c := range conns {
			hostSet[hostFromTarget(c.Target)] = true
		}

		newHosts := make([]string, 0, len(hostSet))
		for h := range hostSet {
			newHosts = append(newHosts, h)
		}

		// Only rebuild host list if hosts changed
		if !sameStrings(newHosts, ui.hosts) {
			ui.hosts = newHosts
			prevSel := ui.selHost
			ui.hostList.Clear()
			ui.hostList.AddItem("* (all)", "", 0, nil)
			selIdx := 0
			for i, h := range ui.hosts {
				ui.hostList.AddItem(h, "", 0, nil)
				if h == prevSel {
					selIdx = i + 1
				}
			}
			ui.hostList.SetCurrentItem(selIdx)
		}

		prevSel := ui.selConn
		ui.rebuildTable()

		if prevSel >= 0 && prevSel < len(ui.filtered) {
			ui.selConn = prevSel
			ui.reqTable.Select(prevSel+1, 0)
		}
		ui.updateDetail()
	})
}

func hostFromTarget(target string) string {
	for i := len(target) - 1; i >= 0; i-- {
		if target[i] == ':' {
			return target[:i]
		}
	}
	return target
}

func sameStrings(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	set := make(map[string]bool, len(a))
	for _, s := range a {
		set[s] = true
	}
	for _, s := range b {
		if !set[s] {
			return false
		}
	}
	return true
}
