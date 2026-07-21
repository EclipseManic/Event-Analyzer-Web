const { createApp } = Vue;

createApp({
  data() {
    return {
      activeTab: "overview",
      activeSubTab: "events",
      investigations: [],
      selectedId: "",
      iocs: [],
      sigmaAlerts: [],
      iocPage: 1,
      iocPerPage: 50,
      iocTotal: 0,
      iocSummary: { types: {}, total: 0 },
      iocFilterType: "",
      iocSearch: "",
      expandedIocId: null,
      loadingIocs: false,
      loadingSigma: false,
      _subTabCache: {},
      sigmaPage: 1,
      sigmaPerPage: 20,
      sigmaTotal: 0,
      sigmaSummary: { levels: {}, total: 0 },
      sigmaFilterLevel: "",
      sigmaSearch: "",
      sigmaError: "",
      noteContent: "",
      savingNote: false,
      loadingNotes: false,
      showNotePreview: false,
      events: [],
      totalEvents: 0,
      page: 1,
      limit: (() => {
        const cfg = window.__APP_CONFIG__ || {};
        const raw = Number(cfg.pageLimit);
        return Number.isFinite(raw) && raw > 0 ? raw : 200;
      })(),
      sort: "asc",
      filters: {
        search: "",
        event_id: "",
        channel: "",
        process_name: "",
        command_line: "",
        user_name: "",
        hostname: "",
        source_file: "",
        start_time: "",
        end_time: "",
      },
      channels: [],
      sourceFiles: [],
      upload: {
        modalOpen: false,
        locked: false,
        invId: "",
        done: false,
        startedAt: 0,
        elapsedMs: 0,
        pollTimer: null,
        tickTimer: null,
        analysis: { stage: "", percent: 0, detail: "" },
        name: "",
        folderNames: [],
        files: [],
        progress: 0,
        error: "",
      },
      uploading: false,
      progress: { stage: "", percent: 0 },
      eventDetail: null,
      selectedEventId: "",
      selectedEventIndex: -1,
      detailHeight: 260,
      resizing: false,
      resizeStartY: 0,
      resizeStartHeight: 0,
      boundResizeMove: null,
      boundResizeStop: null,
      refreshTimer: null,
      loadingEvents: false,
      pendingEventReload: null,
      ingestCompleteSeen: false,
      selectedEventIds: new Set(), // kept for backward compat but no longer used
      expandedSummary: null,
      bookmarkedIds: [],
      sigmaDetail: null,
      sigmaDetailLoading: false,
      toasts: [],
      navStack: [],
      _navAbortController: null,
      _detailCache: {},
      _cachedFieldRows: [],
      _cachedGroupedFields: [],
      lastSavedNote: '',
      _loadingNoteGuard: false,
      _fetchingNav: false,
      _pendingNavId: null,
      sigmaSelectedEvent: null,
    };
  },
  computed: {
    selectedInvestigation() {
      return this.investigations.find((inv) => inv.id === this.selectedId);
    },
    totalPages() {
      return Math.max(1, Math.ceil(this.totalEvents / this.limit));
    },
    iocTotalPages() {
      return Math.max(1, Math.ceil(this.iocTotal / this.iocPerPage));
    },
    filteredIocs() {
      const q = this.iocSearch.trim().toLowerCase();
      if (!q) return this.iocs;
      return this.iocs.filter(ioc => String(ioc.value).toLowerCase().includes(q));
    },
    sigmaTotalPages() {
      return Math.max(1, Math.ceil(this.sigmaTotal / this.sigmaPerPage));
    },
    filteredSigma() {
      const q = this.sigmaSearch.trim().toLowerCase();
      if (!q) return this.sigmaAlerts;
      return this.sigmaAlerts.filter(g => {
        const title = String(g.rule_title || '').toLowerCase();
        const desc = String(g.description || '').toLowerCase();
        const mt = (g.mitre_techniques || []).some(t => String(t.id || '').toLowerCase().includes(q) || String(t.name || '').toLowerCase().includes(q));
        return title.includes(q) || desc.includes(q) || mt;
      });
    },
    activeFilterList() {
      const list = [];
      const labels = { search:'Search', event_id:'Event ID', channel:'Channel', process_name:'Process', command_line:'CmdLine', user_name:'User', hostname:'Hostname', source_file:'File', start_time:'Start', end_time:'End' };
      Object.entries(this.filters).forEach(([k,v]) => {
        if (String(v||'').trim()) list.push({ key: k, label: labels[k]||k, value: v });
      });
      if (this.sort !== 'asc') list.push({ key:'sort', label:'Sort', value: this.sort });
      return list;
    },
    selectedEventSerial() {
      if (!this.eventDetail) return "";
      return this.eventDetail.event_number || "";
    },
    detailHeaderItems() {
      if (!this.eventDetail) return [];
      const items = [];
      const add = (key, label, value) => {
        if (this.isEmptyDetailValue(value)) return;
        items.push({
          key,
          label,
          value: this.formatDetailValue(value),
        });
      };

      const src = this.eventDetail.source_file || this.eventDetail.channel;
      add("source", "Source", src);
      if (this.eventDetail.ioc_count > 0) {
        add("ioc", "IOCs", String(this.eventDetail.ioc_count));
      }
      if (this.eventDetail.sigma_count > 0) {
        add("sigma", "Sigma", String(this.eventDetail.sigma_count));
      }

      return items;
    },
    detailSummaryItems() {
      if (!this.eventDetail) return [];
      const items = [];
      const add = (key, label, value, options = {}) => {
        if (this.isEmptyDetailValue(value)) return;
        items.push({
          key,
          label,
          value: this.formatDetailValue(value),
          empty: this.isEmptyDetailValue(value),
          tone: this.detailTone(key, value),
          wide: options.wide === true,
        });
      };

      add("event_id", "Event ID", this.eventDetail.event_id);
      add("event_record_id", "Record", this.eventDetail.event_record_id);
      add("timestamp", "Time", this.formatTime(this.eventDetail.timestamp));
      add("level", "Level", this.eventDetail.level);

      const host = this.eventDetail.hostname || this.eventDetail.computer;
      add("host", "Host", host);

      const user = this.formatUserDisplay();
      add("user", "User", user);

      return items;
    },
    rawFieldRows() {
      if (!this.eventDetail) return [];
      const cacheKey = this.eventDetail.id || this.eventDetail.event_id || '';
      if (this._detailCache[cacheKey]) return this._detailCache[cacheKey].rows;
      return this._cachedFieldRows;
    },
    groupedRawFields() {
      if (!this.eventDetail) return [];
      const cacheKey = this.eventDetail.id || this.eventDetail.event_id || '';
      if (this._detailCache[cacheKey]) return this._detailCache[cacheKey].groups;
      return this._cachedGroupedFields;
    },
  },
  watch: {
    eventDetail: {
      handler(detail) {
        if (!detail) return;
        const key = detail.id || detail.event_id || '';
        if (!key || this._detailCache[key]) return;
        const t0 = performance.now();
        const cached = this._buildFieldCache(detail);
        this._detailCache[key] = cached;
        this._cachedFieldRows = cached.rows;
        this._cachedGroupedFields = cached.groups;
        const t1 = performance.now();
        if (t1 - t0 > 5) console.warn(`cache build: ${(t1-t0).toFixed(1)}ms`);
      },
      immediate: false,
    },
    noteContent(val) {
      if (!this.selectedId) return;
      // Skip auto-save when notes are being loaded from server
      if (this._loadingNoteGuard) return;
      if (this._noteTimer) clearTimeout(this._noteTimer);
      this._noteTimer = setTimeout(() => {
        if (val !== (this.lastSavedNote ?? '')) {
          this.saveNote(true);
        }
      }, 2000);
    },
  },
  mounted() {
    this.refreshInvestigations();
    window.addEventListener("keydown", this.onKeyDown);
    window.addEventListener("resize", this.onWindowResize);
    this.boundResizeMove = (event) => this.handleResizeMove(event);
    this.boundResizeStop = () => this.stopResize();
    this.detailHeight = this.getDefaultDetailHeight();
  },
  beforeUnmount() {
    window.removeEventListener("keydown", this.onKeyDown);
    window.removeEventListener("resize", this.onWindowResize);
    this.stopResize();
    this.stopUploadModalTimers();
    this.stopPolling();
    if (this._noteTimer) clearTimeout(this._noteTimer);
    if (this._navAbortController) this._navAbortController.abort();
  },
  methods: {
    setTab(tab) {
      const next = String(tab || "").trim();
      if (!next || next === this.activeTab) return;
      this.activeTab = next;

      if (next === "overview") {
        this.closeEvent();
        this.stopPolling();
        if (this._noteTimer) clearTimeout(this._noteTimer);
        if (this._navAbortController) this._navAbortController.abort();
        return;
      }

      if (next === "investigation") {
        this.refreshInvestigations().catch(() => {});
        if (this.selectedId) {
          this.pollProgress();
        }
      }
    },
    async startInvestigation() {
      this.setTab("investigation");
      this.openUploadModal();
    },
    async refreshInvestigations() {
      const res = await fetch("/api/investigations");
      this.investigations = await res.json();
      if (this.activeTab !== "investigation") return;
      if (!this.selectedId && this.investigations.length && !this._skipAutoSelect) {
        await this.selectInvestigation(this.investigations[0].id);
      }
    },
    async selectInvestigation(id) {
      if (this.selectedId && this.selectedId !== id) {
        await this.saveNote(true);
      }
      this.closeEvent();
      this.selectedId = id;
      this.page = 1;
      this.ingestCompleteSeen = false;
      this._subTabCache = {};
      this._detailCache = {};
      this._cachedFieldRows = [];
      this._cachedGroupedFields = [];
      this.navStack = [];
      this.sigmaDetail = null;
      this.sigmaAlerts = [];
      this.sigmaTotal = 0;
      this.sigmaSummary = { levels: {}, total: 0 };
      this.sigmaPage = 1;
      this.sigmaFilterLevel = "";
      this.sigmaSearch = "";
      this.loadingSigma = false;
      this.pollProgress();
      await Promise.all([
        this.loadFilterOptions(),
        this.loadBookmarks(),
        this.loadEvents(),
        this.loadSubTabData(),
      ]);
    },
    setSubTab(tab) {
      const prev = this.activeSubTab;
      if (prev !== tab) {
        if (prev === "iocs") {
          this._subTabCache[`${this.selectedId}-iocs`] = { page: this.iocPage, filter: this.iocFilterType };
        } else if (prev === "sigma") {
          this._subTabCache[`${this.selectedId}-sigma`] = { page: this.sigmaPage, filter: this.sigmaFilterLevel };
        }
      }
      this.activeSubTab = tab;
      // Filter out previous subtab, sigma, and event nav entries to prevent breadcrumb accumulation
      this.navStack = this.navStack.filter(n => n.type !== 'subtab' && n.type !== 'sigma' && n.type !== 'event');
      if (this.sigmaDetail && tab !== "sigma") {
        this.closeSigmaDetail();
      }
      this.navStack.push({ label: tab.charAt(0).toUpperCase() + tab.slice(1), type: 'subtab' });
      this.loadSubTabData();
    },
    async loadSubTabData() {
      if (!this.selectedId) return;
      try {
        if (this.activeSubTab === "iocs") {
          const cached = this._subTabCache[`${this.selectedId}-iocs`];
          if (!cached) {
            this.iocPage = 1;
            this.iocFilterType = "";
          } else {
            this.iocPage = cached.page;
            this.iocFilterType = cached.filter;
          }
          await Promise.all([this.loadIocPage(), this.loadIocSummary()]);
        } else if (this.activeSubTab === "sigma") {
          const cached = this._subTabCache[`${this.selectedId}-sigma`];
          if (!cached) {
            this.sigmaPage = 1;
            this.sigmaFilterLevel = "";
          } else {
            this.sigmaPage = cached.page;
            this.sigmaFilterLevel = cached.filter;
          }
          await Promise.all([this.loadSigmaPage(), this.loadSigmaSummary()]);
        } else if (this.activeSubTab === "notes") {
          // Clear pending auto-save timer to prevent race condition
          if (this._noteTimer) clearTimeout(this._noteTimer);
          this.loadingNotes = true;
          this._loadingNoteGuard = true;
          try {
            const res = await fetch(`/api/investigations/${this.selectedId}/notes`);
            if (!res.ok) throw new Error(`HTTP ${res.status}`);
            const data = await res.json();
            this.noteContent = data.content || "";
            this.lastSavedNote = this.noteContent;
          } finally {
            this.loadingNotes = false;
            // Use nextTick to ensure the watcher triggered by noteContent assignment is skipped
            this.$nextTick(() => { this._loadingNoteGuard = false; });
          }
        }
      } catch (err) {
        console.error("loadSubTabData error:", err);
      }
    },
    async loadIocPage() {
      if (!this.selectedId) return;
      this.loadingIocs = true;
      try {
        let url = `/api/investigations/${this.selectedId}/iocs?page=${this.iocPage}&per_page=${this.iocPerPage}`;
        if (this.iocFilterType) url += `&type=${encodeURIComponent(this.iocFilterType)}`;
        const res = await fetch(url);
        if (!res.ok) throw new Error(`HTTP ${res.status}`);
        const data = await res.json();
        this.iocs = data.items;
        this.iocTotal = data.total;
      } catch (err) {
        console.error("loadIocPage error:", err);
      } finally {
        this.loadingIocs = false;
      }
    },
    async loadIocSummary() {
      if (!this.selectedId) return;
      try {
        const res = await fetch(`/api/investigations/${this.selectedId}/iocs/summary`);
        if (!res.ok) throw new Error(`HTTP ${res.status}`);
        this.iocSummary = await res.json();
      } catch (err) {
        console.error("loadIocSummary error:", err);
      }
    },
    viewEventsForIoc(ioc) {
      this.filters.search = ioc.value;
      this.page = 1;
      this.activeSubTab = 'events';
      this.loadEvents();
    },
    filterIocByType(type) {
      this.iocFilterType = this.iocFilterType === type ? "" : type;
      this.iocPage = 1;
      this.iocSearch = "";
      this.loadIocPage();
    },
    async nextIocPage() {
      if (this.iocPage >= this.iocTotalPages) return;
      this.iocPage++;
      await this.loadIocPage();
    },
    async prevIocPage() {
      if (this.iocPage <= 1) return;
      this.iocPage--;
      await this.loadIocPage();
    },
    toggleIocContext(id) {
      this.expandedIocId = this.expandedIocId === id ? null : id;
    },
    async loadSigmaPage() {
      if (!this.selectedId) return;
      this.loadingSigma = true;
      this.sigmaError = "";
      try {
        let url = `/api/investigations/${this.selectedId}/sigma?page=${this.sigmaPage}&per_page=${this.sigmaPerPage}`;
        if (this.sigmaFilterLevel) url += `&level=${encodeURIComponent(this.sigmaFilterLevel)}`;
        const res = await fetch(url);
        if (!res.ok) throw new Error(`HTTP ${res.status}`);
        const data = await res.json();
        this.sigmaAlerts = data.items;
        this.sigmaTotal = data.total;
      } catch (err) {
        this.sigmaError = "Failed to load Sigma rules";
        console.error("loadSigmaPage error:", err);
      } finally {
        this.loadingSigma = false;
      }
    },
    async loadSigmaSummary() {
      if (!this.selectedId) return;
      this.sigmaError = "";
      try {
        const res = await fetch(`/api/investigations/${this.selectedId}/sigma/summary`);
        if (!res.ok) throw new Error(`HTTP ${res.status}`);
        this.sigmaSummary = await res.json();
      } catch (err) {
        this.sigmaError = "Failed to load Sigma summary";
        console.error("loadSigmaSummary error:", err);
      }
    },
    async filterSigmaByLevel(level) {
      this.sigmaFilterLevel = this.sigmaFilterLevel === level ? "" : level;
      this.sigmaPage = 1;
      this.sigmaDetail = null;
      await Promise.all([this.loadSigmaPage(), this.loadSigmaSummary()]);
    },
    async nextSigmaPage() {
      if (this.sigmaPage >= this.sigmaTotalPages) return;
      this.sigmaPage++;
      await this.loadSigmaPage();
    },
    async prevSigmaPage() {
      if (this.sigmaPage <= 1) return;
      this.sigmaPage--;
      await this.loadSigmaPage();
    },
    exportSigma(fmt) {
      if (!this.selectedId) return;
      const rows = this.filteredSigma;
      if (!rows.length) return;
      const data = rows.map(g => ({
        rule_id: g.rule_id,
        rule_title: g.rule_title || '',
        level: g.level,
        match_count: g.match_count,
        description: g.description || '',
        mitre_techniques: (g.mitre_techniques || []).map(m => `${m.id} ${m.name}`).join('; ')
      }));
      if (fmt === 'json') {
        const blob = new Blob([JSON.stringify(data, null, 2)], { type: 'application/json' });
        const url = URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.href = url; a.download = `${this.selectedId}_sigma.json`; a.click();
        URL.revokeObjectURL(url);
      } else {
        const header = 'rule_id,rule_title,level,match_count,description,mitre_techniques';
        const rows_csv = data.map(r =>
          [r.rule_id, r.rule_title, r.level, r.match_count, `"${(r.description||'').replace(/"/g,'""')}"`, `"${r.mitre_techniques.replace(/"/g,'""')}"`].join(',')
        );
        const blob = new Blob([header + '\n' + rows_csv.join('\n')], { type: 'text/csv' });
        const url = URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.href = url; a.download = `${this.selectedId}_sigma.csv`; a.click();
        URL.revokeObjectURL(url);
      }
    },
    async openSigmaDetail(sigmaMatch) {
      if (!this.selectedId || !sigmaMatch) return;
      if (this.sigmaDetail?.rule?.rule_id === sigmaMatch.rule_id) {
        this.closeSigmaDetail();
        return;
      }
      this.sigmaDetail = null;
      this.sigmaDetailLoading = true;
      this.sigmaError = "";
      try {
        const res = await fetch(`/api/investigations/${this.selectedId}/sigma/events?rule_id=${encodeURIComponent(sigmaMatch.rule_id)}`);
        if (!res.ok) throw new Error(`HTTP ${res.status}`);
        this.sigmaDetail = await res.json();
        this.pushNav('Rule: ' + (sigmaMatch.rule_title || sigmaMatch.rule_id), 'sigma', () => { this.closeSigmaDetail(); });
      } catch (err) {
        this.sigmaError = "Failed to load rule details";
        console.error("openSigmaDetail error:", err);
      } finally {
        this.sigmaDetailLoading = false;
      }
    },
    closeSigmaDetail() {
      this.sigmaDetail = null;
      this.sigmaError = "";
      this.navStack = this.navStack.filter(n => n.type !== 'sigma');
    },
    async loadBookmarks() {
      if (!this.selectedId) return;
      try {
        const res = await fetch(`/api/investigations/${this.selectedId}/bookmarks`);
        if (!res.ok) throw new Error(`HTTP ${res.status}`);
        const data = await res.json();
        this.bookmarkedIds = data.ids || [];
      } catch (err) {
        console.error("loadBookmarks error:", err);
      }
    },
    isBookmarked(eventId) {
      return this.bookmarkedIds.includes(eventId);
    },
    async toggleBookmark(eventId) {
      if (!this.selectedId) return;
      try {
        const wasBookmarked = this.isBookmarked(eventId);
        if (wasBookmarked) {
          await fetch(`/api/investigations/${this.selectedId}/bookmarks/${eventId}`, { method: "DELETE" });
          this.bookmarkedIds = this.bookmarkedIds.filter(id => id !== eventId);
          this.addToast('Bookmark removed', 'success');
        } else {
          await fetch(`/api/investigations/${this.selectedId}/bookmarks`, {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ event_id: eventId }),
          });
          this.bookmarkedIds.push(eventId);
          this.addToast('Bookmarked', 'success');
        }
      } catch (err) {
        console.error("toggleBookmark error:", err);
        this.addToast('Failed to toggle bookmark', 'error');
      }
    },
    pushNav(label, type, action) {
      this.navStack.push({ label, type, action });
    },
    navTo(index) {
      const target = this.navStack[index];
      if (!target) return;
      this.navStack = this.navStack.slice(0, index);
      if (target.action) target.action();
    },
    async viewSigmaEvent(eventRow) {
      if (!this.selectedId) return;
      const id = eventRow.id || eventRow.event_id;
      if (!id) return;
      this.sigmaSelectedEvent = { loading: true };
      try {
        const res = await fetch(`/api/investigations/${this.selectedId}/events/${id}`);
        if (res.ok) {
          this.sigmaSelectedEvent = await res.json();
        } else {
          this.sigmaSelectedEvent = null;
        }
      } catch (_) {
        this.sigmaSelectedEvent = null;
      }
    },
    closeSigmaEvent() {
      this.sigmaSelectedEvent = null;
    },
    async jumpToEvent(eventRow) {
      this.closeSigmaDetail();
      this.activeSubTab = "events";
      this.activeTab = "investigation";
      const lookupId = eventRow.id || eventRow.event_id;
      if (!lookupId) { this.setSubTab("events"); return; }
      try {
        const res = await fetch(`/api/investigations/${this.selectedId}/events/${lookupId}`);
        if (res.ok) {
          const evt = await res.json();
          this.setSubTab("events");
          this.pushNav('Event #' + (evt.event_number || evt.event_id), 'event', () => { this.closeEvent(); });
          this.openEvent(evt.id || evt.event_id, -1);
          return;
        }
      } catch (_) {}
      this.setSubTab("events");
      const origPage = this.page;
      const origTotal = this.totalPages;
      for (let p = 1; p <= origTotal; p++) {
        this.page = p;
        await this.loadEvents();
        const evt = this.events.find(e =>
          String(e.event_id) === String(eventRow.event_id) &&
          String(e.event_number) === String(eventRow.event_number)
        );
        if (evt) {
          const idx = this.events.indexOf(evt);
          this.openEvent(evt.id, idx);
          return;
        }
      }
      this.page = origPage;
      await this.loadEvents();
    },
    async saveNote(silent) {
      if (!this.selectedId) return;
      if (!silent) this.savingNote = true;
      try {
        await fetch(`/api/investigations/${this.selectedId}/notes`, {
          method: "PUT",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ content: this.noteContent }),
        });
        this.lastSavedNote = this.noteContent;
      } finally {
        if (!silent) this.savingNote = false;
      }
    },
    async deleteSelectedInvestigation() {
      if (!this.selectedId) return;

      const deletedId = this.selectedId;
      const res = await fetch(`/api/investigations/${deletedId}`, { method: "DELETE" });
      if (!res.ok) return;

      this.stopPolling();
      if (this._noteTimer) clearTimeout(this._noteTimer);
      if (this._navAbortController) this._navAbortController.abort();
      this.closeEvent();
      this.selectedId = "";
      this.events = [];
      this.totalEvents = 0;
      this.channels = [];
      this.providers = [];
      this.sourceFiles = [];
      this.progress = { stage: "", percent: 0 };
      this._skipAutoSelect = true;
      await this.refreshInvestigations();
      this._skipAutoSelect = false;
    },
    async loadFilterOptions() {
      if (!this.selectedId) return;
      const [channels, files] = await Promise.all([
        fetch(`/api/investigations/${this.selectedId}/channels`).then((r) => r.json()),
        fetch(`/api/investigations/${this.selectedId}/source-files`).then((r) => r.json()),
      ]);
      this.channels = channels;
      this.sourceFiles = files;
    },
    async loadEvents(options = {}) {
      if (!this.selectedId) return;
      if (this.loadingEvents) {
        this.pendingEventReload = options;
        return;
      }
      this.loadingEvents = true;
      const preserveDetail = options && options.preserveDetail === true;
      try {
        const params = this.buildQuery();
        const res = await fetch(`/api/investigations/${this.selectedId}/events?${params}`);
        const data = await res.json();
        this.events = data.items || [];
        this.totalEvents = data.count || 0;
        if (!this.events.length) {
          if (!preserveDetail) {
            this.closeEvent();
          }
          return;
        }
        if (this.selectedEventId) {
          const idx = this.events.findIndex((evt) => evt.id === this.selectedEventId);
          if (idx === -1) {
            if (!preserveDetail) {
              this.closeEvent();
            } else {
              this.selectedEventIndex = -1;
            }
          } else {
            this.selectedEventIndex = idx;
          }
        }
      } finally {
        this.loadingEvents = false;
        if (this.pendingEventReload) {
          const pending = this.pendingEventReload;
          this.pendingEventReload = null;
          await this.loadEvents(pending);
        }
      }
    },
    buildQuery() {
      const params = new URLSearchParams();
      Object.entries(this.filters).forEach(([key, val]) => {
        const raw = String(val ?? "").trim();
        if (!raw) return;
        if (key === "start_time" || key === "end_time") {
          const normalized = this.normalizeTimeFilter(raw);
          if (normalized) {
            params.append(key, normalized);
          }
          return;
        }
        params.append(key, raw);
      });
      params.append("sort", this.sort);
      params.append("limit", String(this.limit));
      params.append("offset", String((this.page - 1) * this.limit));
      return params.toString();
    },
    async applyFilters() {
      this.page = 1;
      await this.loadEvents();
    },
    removeFilter(key) {
      if (key === 'sort') { this.sort = 'asc'; this.applyFilters(); return; }
      this.filters[key] = '';
      this.applyFilters();
    },
    async resetFilters() {
      this.filters = {
        search: "",
        event_id: "",
        channel: "",
        user_name: "",
        hostname: "",
        source_file: "",
        start_time: "",
        end_time: "",
      };
      this.sort = "asc";
      await this.applyFilters();
    },
    async nextPage() {
      if (this.page >= this.totalPages) return;
      this.page += 1;
      await this.loadEvents();
    },
    async prevPage() {
      if (this.page <= 1) return;
      this.page -= 1;
      await this.loadEvents();
    },
    openUploadModal() {
      this.activeTab = "investigation";
      this.resetUploadModalState();
      this.upload.modalOpen = true;
      this.$nextTick(() => {
        const input = this.$refs.evtxFileInput;
        if (input) input.value = "";
        const folderInput = this.$refs.evtxFolderInput;
        if (folderInput) folderInput.value = "";
      });
    },
    closeUploadModal() {
      if (this.upload.locked) return;
      this.stopUploadModalTimers();
      this.upload.modalOpen = false;
      this.resetUploadModalState();
    },
    resetUploadModalState() {
      this.upload.locked = false;
      this.upload.invId = "";
      this.upload.done = false;
      this.upload.startedAt = 0;
      this.upload.elapsedMs = 0;
      this.upload.progress = 0;
      this.upload.error = "";
      this.upload.analysis = { stage: "", percent: 0, detail: "" };
      this.upload.name = "";
      this.upload.folderNames = [];
      this.upload.files = [];
      this.uploading = false;
    },
    stopUploadModalTimers() {
      if (this.upload.pollTimer) {
        clearInterval(this.upload.pollTimer);
        this.upload.pollTimer = null;
      }
      if (this.upload.tickTimer) {
        clearInterval(this.upload.tickTimer);
        this.upload.tickTimer = null;
      }
    },
    startUploadElapsedTimer() {
      if (!this.upload.startedAt) return;
      if (this.upload.tickTimer) clearInterval(this.upload.tickTimer);
      this.upload.tickTimer = setInterval(() => {
        this.upload.elapsedMs = Math.max(0, Date.now() - this.upload.startedAt);
      }, 200);
    },
    async pollUploadedInvestigationProgressOnce() {
      if (!this.upload.invId) return;
      const res = await fetch(`/api/investigations/${this.upload.invId}/progress`);
      const next = await res.json();
      const stage = (next.stage || "").trim();
      this.upload.analysis = {
        stage: stage === "unknown" ? "" : stage,
        percent: Number.isFinite(Number(next.percent)) ? Number(next.percent) : 0,
        detail: next.detail || "",
      };

      const done = this.upload.analysis.stage === "complete" || this.upload.analysis.stage === "complete_with_errors";
      if (!done) return;

      this.upload.done = true;
      this.upload.locked = false;
      this.stopUploadModalTimers();
      this.upload.elapsedMs = Math.max(0, Date.now() - (this.upload.startedAt || Date.now()));
      await this.refreshInvestigations();
    },
    uploadFiles() {
      if (!this.upload.files.length || this.uploading) return;

      this.stopUploadModalTimers();
      this.upload.locked = true;
      this.upload.invId = "";
      this.upload.done = false;
      this.upload.progress = 0;
      this.upload.error = "";
      this.upload.analysis = { stage: "", percent: 0, detail: "" };
      this.upload.startedAt = Date.now();
      this.upload.elapsedMs = 0;
      this.startUploadElapsedTimer();

      this.uploading = true;

      if (!this.upload.name) {
        const derived = this.deriveInvestigationName(this.upload.files, this.upload.folderNames);
        if (derived) this.upload.name = derived;
      }

      const form = new FormData();
      this.upload.files.forEach((file) => form.append("files", file));
      if (this.upload.name) form.append("name", this.upload.name);

      const xhr = new XMLHttpRequest();
      xhr.open("POST", "/api/upload");
      xhr.upload.onprogress = (evt) => {
        if (evt.lengthComputable) {
          this.upload.progress = Math.round((evt.loaded / evt.total) * 100);
        }
      };
      xhr.onreadystatechange = async () => {
        if (xhr.readyState !== 4) return;
        this.uploading = false;

        if (xhr.status >= 200 && xhr.status < 300) {
          const data = JSON.parse(xhr.responseText);
          this.upload.invId = data.investigation_id || "";
          await this.refreshInvestigations();

          if (!this.upload.invId) {
            this.upload.error = "Upload succeeded but no investigation id was returned.";
            this.upload.locked = false;
            this.stopUploadModalTimers();
            return;
          }

          await this.pollUploadedInvestigationProgressOnce();
          if (!this.upload.done) {
            this.upload.pollTimer = setInterval(() => {
              this.pollUploadedInvestigationProgressOnce().catch(() => {});
            }, 1500);
          }
        } else {
          try {
            const data = JSON.parse(xhr.responseText);
            this.upload.error = data.error || "Upload failed";
          } catch (e) {
            this.upload.error = "Upload failed";
          }
          this.upload.locked = false;
          this.stopUploadModalTimers();
        }
      };
      xhr.send(form);
    },
    async viewUploadedInvestigation() {
      if (!this.upload.invId) return;
      this.activeTab = "investigation";
      const invId = this.upload.invId;
      await this.refreshInvestigations();
      await this.selectInvestigation(invId);
      this.closeUploadModal();
    },
    formatDuration(ms) {
      const total = Math.max(0, Math.floor(Number(ms || 0) / 1000));
      const minutes = Math.floor(total / 60);
      const seconds = total % 60;
      return minutes > 0 ? `${minutes}m ${seconds}s` : `${seconds}s`;
    },
    fileKey(file) {
      const rel = file.webkitRelativePath || file.name || "";
      return `${rel}|${file.size}|${file.lastModified}`;
    },
    deriveInvestigationName(files, folderNames) {
      const folders = Array.isArray(folderNames) ? folderNames : [];
      if (folders.length) {
        return folders[0];
      }
      if (!files || !files.length) return "";
      const first = files[0];
      const relPath = first.webkitRelativePath || "";
      if (relPath) {
        const segment = relPath.split("/")[0];
        if (segment) return segment;
      }
      const raw = first.name || "";
      return raw.replace(/\.evtx$/i, "");
    },
    addSelectedFiles(fileList, source) {
      const incoming = Array.from(fileList || []);
      if (!incoming.length) return;
      const evtxFiles = incoming.filter((file) => String(file.name || "").toLowerCase().endsWith(".evtx"));
      const skipped = incoming.length - evtxFiles.length;

      const existing = new Map(this.upload.files.map((file) => [this.fileKey(file), file]));
      evtxFiles.forEach((file) => existing.set(this.fileKey(file), file));
      this.upload.files = Array.from(existing.values());

      if (source === "folder") {
        const folderSet = new Set(this.upload.folderNames);
        evtxFiles.forEach((file) => {
          const rel = file.webkitRelativePath || "";
          const top = rel.split("/")[0];
          if (top) folderSet.add(top);
        });
        this.upload.folderNames = Array.from(folderSet.values());
      }

      if (!this.upload.name) {
        const derived = this.deriveInvestigationName(this.upload.files, this.upload.folderNames);
        if (derived) this.upload.name = derived;
      }

      if (skipped > 0) {
        this.upload.error = `Skipped ${skipped} non-EVTX file${skipped > 1 ? "s" : ""}.`;
      } else {
        this.upload.error = "";
      }
    },
    onFileChange(event) {
      this.addSelectedFiles(event.target.files, "file");
    },
    onFolderChange(event) {
      this.addSelectedFiles(event.target.files, "folder");
    },
    toggleEvent(evt, index) {
      if (this.selectedEventId === evt.id) {
        this.closeEvent();
        return;
      }
      this.openEvent(evt.id, index);
    },
    async openEvent(id, index, signal) {
      if (!this.selectedId) return;
      this.selectedEventId = id;
      this.selectedEventIndex = index;
      this.detailHeight = this.clampDetailHeight(this.detailHeight);
      try {
        const res = await fetch(`/api/investigations/${this.selectedId}/events/${id}`, { signal });
        if (!res.ok) return;
        const detail = await res.json();
        if (this.selectedEventId === id) {
          this.eventDetail = detail;
        }
      } catch (err) {
        if (err.name === 'AbortError') return;
        console.error('openEvent error:', err);
      }
    },
    closeEvent() {
      this.eventDetail = null;
      this.selectedEventId = "";
      this.selectedEventIndex = -1;
      this._cachedFieldRows = [];
      this._cachedGroupedFields = [];
    },
    exportEvents(fmt) {
      if (!this.selectedId) return;
      const params = this.buildQuery();
      window.open(`/api/investigations/${this.selectedId}/events/export?format=${fmt}&${params}`, "_blank");
    },
    exportIocs(fmt) {
      if (!this.selectedId) return;
      let url = `/api/investigations/${this.selectedId}/iocs/export?format=${fmt}`;
      if (this.iocFilterType) url += `&type=${encodeURIComponent(this.iocFilterType)}`;
      window.open(url, "_blank");
    },
    exportReport() {
      if (!this.selectedId) return;
      window.open(`/api/investigations/${this.selectedId}/report`, "_blank");
    },
    pollProgress() {
      if (this.refreshTimer) clearInterval(this.refreshTimer);
      if (!this.selectedId) return;
      this.refreshTimer = setInterval(async () => {
        if (!this.selectedId) { this.stopPolling(); return; }
        const res = await fetch(`/api/investigations/${this.selectedId}/progress`);
        if (!res.ok) return;
        const next = await res.json();
        const done = next.stage === "complete" || next.stage === "complete_with_errors";
        if (done) {
          if (!this.ingestCompleteSeen) {
            this.ingestCompleteSeen = true;
            this.progress = next;
            // Clear sub-tab cache so IOC/Sigma tabs fetch fresh data when switched to
            this._subTabCache = {};
            await this.loadFilterOptions();
            await this.loadEvents();
            if (this.activeSubTab === "iocs") {
              await Promise.all([this.loadIocPage(), this.loadIocSummary()]);
            } else if (this.activeSubTab === "sigma") {
              await Promise.all([this.loadSigmaPage(), this.loadSigmaSummary()]);
            }
          }
          this.stopPolling();
          return;
        }
        const prevPercent = this.progress.percent;
        this.progress = next;
        if (!this.events.length && next.percent > prevPercent) {
          await this.loadEvents();
        }
      }, 3000);
    },
    stopPolling() {
      if (this.refreshTimer) {
        clearInterval(this.refreshTimer);
        this.refreshTimer = null;
      }
    },
    formatTime(ts) {
      if (!ts) return "";
      const raw = String(ts).trim();
      const match = raw.match(
        /^(\d{4}-\d{2}-\d{2})(?:[T\s])(\d{2}:\d{2}:\d{2})(\.\d+)?(?:\s*(Z|[+-]\d{2}:?\d{2}))?$/i
      );
      if (!match) {
        return raw.replace("T", " ");
      }
      const [, datePart, timePart, fraction = "", zoneRaw = ""] = match;
      if (!zoneRaw) {
        return `${datePart} ${timePart}${fraction}`;
      }
      if (/^z$/i.test(zoneRaw)) {
        return `${datePart} ${timePart}${fraction} UTC`;
      }
      const zone = zoneRaw.includes(":")
        ? zoneRaw
        : `${zoneRaw.slice(0, 3)}:${zoneRaw.slice(3)}`;
      return `${datePart} ${timePart}${fraction} UTC${zone}`;
    },
    pretty(obj) {
      return JSON.stringify(obj, null, 2);
    },
    rawEventJson() {
      if (!this.eventDetail) return "";
      if (typeof this.eventDetail.raw_data === "string" && this.eventDetail.raw_data.trim()) {
        return this.eventDetail.raw_data;
      }
      return this.pretty(this.eventDetail);
    },
    rawEventSource() {
      if (!this.eventDetail) return null;

      const raw = this.eventDetail.raw_data;
      if (typeof raw === "string" && raw.trim()) {
        const trimmed = raw.trim();
        try {
          return JSON.parse(trimmed);
        } catch (err) {
          return trimmed;
        }
      }

      if (raw && typeof raw === "object") {
        return raw;
      }

      const fallback = {};
      Object.entries(this.eventDetail).forEach(([key, value]) => {
        if (key === "raw_data") return;
        if (this.isEmptyDetailValue(value)) return;
        fallback[key] = value;
      });
      return fallback;
    },
    flattenRawValue(value, path, rows) {
      const currentPath = path || "raw_data";

      if (Array.isArray(value)) {
        if (!value.length) {
          rows.push(this.makeRawFieldRow(currentPath, value));
          return;
        }
        value.forEach((item, index) => {
          this.flattenRawValue(item, `${currentPath}[${index}]`, rows);
        });
        return;
      }

      if (value && typeof value === "object") {
        const attrs = value["#attributes"];
        const hasText = Object.prototype.hasOwnProperty.call(value, "#text");

        if (hasText) {
          const textPath = this.semanticRawPath(currentPath, attrs);
          const textValue = value["#text"];
          if (Array.isArray(textValue)) {
            textValue.forEach((item, index) => {
              rows.push(this.makeRawFieldRow(`${textPath}[${index}]`, item));
            });
          } else {
            rows.push(this.makeRawFieldRow(textPath, textValue));
          }
          if (attrs && typeof attrs === "object") {
            Object.entries(attrs).forEach(([attrKey, attrValue]) => {
              if (String(attrKey).toLowerCase() === "name") return;
              this.flattenRawValue(attrValue, `${currentPath}.${attrKey}`, rows);
            });
          }
          Object.entries(value).forEach(([key, child]) => {
            if (key === "#text" || key === "#attributes") return;
            this.flattenRawValue(child, `${currentPath}.${key}`, rows);
          });
          return;
        }

        if (attrs && typeof attrs === "object") {
          Object.entries(attrs).forEach(([attrKey, attrValue]) => {
            this.flattenRawValue(attrValue, `${currentPath}.${attrKey}`, rows);
          });
          Object.entries(value).forEach(([key, child]) => {
            if (key === "#attributes") return;
            this.flattenRawValue(child, `${currentPath}.${key}`, rows);
          });
          return;
        }

        const entries = Object.entries(value);
        if (!entries.length) {
          rows.push(this.makeRawFieldRow(currentPath, value));
          return;
        }
        entries.forEach(([key, child]) => {
          const childPath = path ? `${path}.${key}` : key;
          this.flattenRawValue(child, childPath, rows);
        });
        return;
      }

      rows.push(this.makeRawFieldRow(currentPath, value));
    },
    makeRawFieldRow(path, value) {
      return {
        path,
        type: this.rawValueType(value),
        displayValue: this.formatRawValue(value),
      };
    },
    isHeaderRawField(row) {
      if (!this.eventDetail || !row) return false;
      const path = String(row.path || "").toLowerCase();
      const value = this.normalizeComparable(row.displayValue);
      const eventId = this.normalizeComparable(this.eventDetail.event_id);
      const recordId = this.normalizeComparable(this.eventDetail.event_record_id);
      const timestamp = this.normalizeComparable(this.eventDetail.timestamp);
      const level = this.normalizeComparable(this.eventDetail.level);
      const host = this.normalizeComparable(this.eventDetail.hostname || this.eventDetail.computer);
      const channel = this.normalizeComparable(this.eventDetail.channel);
      const provider = this.normalizeComparable(this.eventDetail.provider);

      if (eventId && value === eventId && /event\.system\.eventid($|\.#text$)/.test(path)) {
        return true;
      }

      if (recordId && value === recordId && /event\.system\.eventrecordid$/.test(path)) {
        return true;
      }

      if (timestamp && value === timestamp && /event\.system\.timecreated\.systemtime$/.test(path)) {
        return true;
      }

      if (level && value === level && /event\.system\.level$/.test(path)) {
        return true;
      }

      if (host && value === host && /event\.system\.computer$/.test(path)) {
        return true;
      }

      if (channel && value === channel && /(^|\.|\/)channel$/.test(path)) {
        return true;
      }

      if (!path.includes(".")) {
        return ["event_id", "event_record_id", "timestamp", "level", "computer", "hostname", "channel", "provider"].includes(path);
      }

      if (!provider || value !== provider) {
        return false;
      }

      return (
        /(^|\.|\/)provider(\.|\/)?name$/.test(path) ||
        /(^|\.|\/)provider$/.test(path) ||
        /eventsource(name)?$/.test(path)
      );
    },
    normalizeComparable(value) {
      if (value === null || value === undefined) return "";
      return String(value).trim().toLowerCase();
    },
    semanticRawPath(path, attrs) {
      if (!attrs || typeof attrs !== "object") return path;
      const name = attrs.Name || attrs.name;
      if (!name) return path;
      const cleanName = String(name).trim();
      if (!cleanName) return path;
      if (/\.Data\[\d+\]$/i.test(path)) {
        return path.replace(/\.Data\[\d+\]$/i, `.${cleanName}`);
      }
      if (/\.Data$/i.test(path)) {
        return `${path}.${cleanName}`;
      }
      return path;
    },
    formatRawPath(path) {
      return String(path || "")
        .replace(/#/g, "")
        .replace(/\.(\d+)/g, "[$1]")
        .replace(/\./g, " / ");
    },
    rawFieldCategory(path) {
      const key = String(path || "").toLowerCase();
      if (/time|date|timestamp|created/.test(key)) return "time";
      if (/service|eventsource|param|perimeter|perimeterx/.test(key)) return "service";
      if (/computer|host|machine|workstation|domain|user|sid|account|subject|target/.test(key)) return "identity";
      if (/command|script|powershell|cmdline/.test(key)) return "command";
      if (/process|image|parent|executable|appname/.test(key)) return "process";
      if (/sourceip|destinationip|destip|ipaddress|address|hostname|dns|query|url|uri/.test(key)) return "network";
      if (/sourceport|destinationport|destport|port/.test(key)) return "port";
      if (/guid|activityid|correlation|processguid|logonguid/.test(key)) return "guid";
      if (/hash|sha|md5|signature|signed|cert/.test(key)) return "hash";
      if (/registry|regkey|regvalue/.test(key)) return "registry";
      if (/file|path|directory|targetfilename|objectname/.test(key)) return "file";
      if (/logon|auth|security|status|failure|access|privilege/.test(key)) return "security";
      if (/eventid|recordid|level|task|opcode|keywords|channel|provider|system/.test(key)) return "event";
      if (/data|eventdata|userdata|#text|param|message|description/.test(key)) return "data";
      return "other";
    },
    rawFieldPriority(path) {
      const key = String(path || "").toLowerCase();
      if (/event\.system\.eventid\.(qualifiers|#attributes|value)$/i.test(key)) return 18;
      const orderedPatterns = [
        /event\.system\.eventid\.#text$|event\.system\.eventid$|eventid$/,
        /event\.system\.channel|channel$/,
        /event\.system\.provider\.name$|provider\.name$|provider$/,
        /service|eventsource|perimeter|perimeterx/,
        /event\.system\.computer|computer$|hostname|host$/,
        /username|user_name|accountname|targetusername|subjectusername|user$/,
        /domain|sid/,
        /timecreated|systemtime|timestamp|time$/,
        /commandline|command|scriptblock|script|powershell/,
        /process|image|parentprocess|executable|appname/,
        /sourceip|destinationip|destip|ipaddress|address|queryname|hostname|url|uri/,
        /sourceport|destinationport|destport|port/,
        /guid|activityid|correlation/,
        /hash|sha|md5/,
        /file|path|directory|targetfilename|objectname/,
        /registry|key|value/,
        /logon|auth|security|status|failure|access|privilege/,
        /level|task|opcode|keywords|recordid/,
        /eventdata|userdata|data|param|message|description|#text/,
      ];
      const found = orderedPatterns.findIndex((pattern) => pattern.test(key));
      return found === -1 ? orderedPatterns.length : found;
    },
    rawValueRank(row) {
      if (!row) return 2;
      const value = String(row.displayValue || "").trim();
      if (["empty", "null", "undefined"].includes(row.type) || !value || value === "(empty string)") return 2;
      const normalized = value.replace(/\u0000/g, "").trim().toLowerCase();
      if (/^[-]+$/.test(normalized)) return 2;
      if (/^(n\/a|na|none|null|nil|undefined|\(null\)|not available|not applicable)$/.test(normalized)) return 2;
      if (/^(0|0x0|0\.0+|false)$/.test(normalized)) return 1;
      if (/^0+$/.test(normalized)) return 1;
      if (/^s-1-0-0$/.test(normalized)) return 1;
      if (/^\{?0{8}-0{4}-0{4}-0{4}-0{12}\}?$/.test(normalized)) return 1;
      return 0;
    },
    rawValueType(value) {
      if (value === null) return "null";
      if (value === undefined) return "undefined";
      if (Array.isArray(value)) return "array";
      if (typeof value === "string") return value === "" ? "empty" : "string";
      if (typeof value === "number") return "number";
      if (typeof value === "boolean") return "boolean";
      if (typeof value === "object") return "object";
      return "string";
    },
    formatRawValue(value) {
      if (value === null) return "null";
      if (value === undefined) return "undefined";
      if (typeof value === "string") return value === "" ? "(empty string)" : value;
      if (typeof value === "object") return JSON.stringify(value, null, 2);
      return String(value);
    },
    escapeRegExp(value) {
      return String(value).replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
    },
    escapeHtml(value) {
      return String(value)
        .replace(/&/g, "&amp;")
        .replace(/</g, "&lt;")
        .replace(/>/g, "&gt;")
        .replace(/\"/g, "&quot;")
        .replace(/'/g, "&#39;");
    },
    highlightText(value) {
      const term = String(this.filters.search || "").trim();
      const text = value === null || value === undefined ? "" : String(value);
      const safeText = this.escapeHtml(text);
      if (!term) return safeText;
      const safeTerm = this.escapeHtml(term);
      const pattern = this.escapeRegExp(safeTerm);
      if (!pattern) return safeText;
      try {
        const regex = new RegExp(pattern, "gi");
        return safeText.replace(regex, (match) => `<mark class="search-hit">${match}</mark>`);
      } catch (err) {
        return safeText;
      }
    },
    orderedDetailKeys() {
      if (!this.eventDetail) return [];
      const preferred = [
        "event_id", "event_record_id", "timestamp", "level", "channel",
        "provider", "computer", "hostname", "user_name", "user_domain",
        "process_name", "process_id", "parent_process", "command_line",
        "description", "source_ip", "source_port", "dest_ip", "dest_port",
        "logon_type", "target_user", "target_domain", "file_path",
        "registry_key", "registry_value", "service_name", "hash_value",
        "task", "opcode", "keywords",
      ];
      const keys = Object.keys(this.eventDetail);
      const known = preferred.filter((key) => keys.includes(key));
      const extra = keys.filter((key) => !preferred.includes(key)).sort();
      return [...known, ...extra];
    },
    detailDisplayKeys() {
      if (!this.eventDetail) return [];
      return this.orderedDetailKeys().filter((key) => this.shouldShowDetailKey(key));
    },
    makeDetailItem(key, label) {
      if (!this.eventDetail || !Object.prototype.hasOwnProperty.call(this.eventDetail, key)) return null;
      const value = this.eventDetail[key];
      return {
        key,
        label: label || this.formatFieldLabel(key),
        value: this.formatDetailValue(value),
        empty: this.isEmptyDetailValue(value),
        tone: this.detailTone(key, value),
      };
    },
    formatFieldLabel(key) {
      return String(key)
        .replace(/_/g, " ")
        .replace(/\b\w/g, (char) => char.toUpperCase());
    },
    formatDetailValue(value) {
      if (value === null || value === undefined) return "null";
      if (value === "") return "empty";
      if (typeof value === "object") return JSON.stringify(value, null, 2);
      return String(value);
    },
    isEmptyDetailValue(value) {
      return value === null || value === undefined || value === "";
    },
    formatUserDisplay() {
      if (!this.eventDetail) return "";
      const userName = this.eventDetail.user_name || "";
      const userDomain = this.eventDetail.user_domain || "";
      if (userName && userDomain) {
        return userName.includes("\\") ? userName : `${userDomain}\\${userName}`;
      }
      return userName || userDomain;
    },
    shouldShowDetailKey(key) {
      const normalized = String(key).toLowerCase();
      if (["event_id", "event_record_id", "timestamp", "level", "computer", "hostname", "user_name", "user_domain"].includes(normalized)) {
        return false;
      }
      if (["id", "investigation_id", "source_file", "raw_data", "event_category"].includes(normalized)) {
        return false;
      }
      return true;
    },
    isCommandField(key) {
      const normalized = String(key).toLowerCase();
      return normalized.includes("command") || normalized.includes("script") || normalized.includes("powershell");
    },
    isEvidenceField(key, value) {
      if (this.isEmptyDetailValue(value)) return false;
      const normalized = String(key).toLowerCase();
      if (this.isCommandField(normalized)) return true;
      if (["description", "raw_data", "message", "xml"].includes(normalized)) return true;
      if (typeof value === "object") return true;
      return String(value).length > 160;
    },
    detailTone(key, value) {
      if (this.isEmptyDetailValue(value)) return "muted";
      const normalized = String(key).toLowerCase();
      const text = this.formatDetailValue(value);
      if (this.isCommandField(normalized)) return /encodedcommand|frombase64string|executionpolicy\s+bypass|invoke-expression|\biex\b|downloadstring|-w\s+hidden|-windowstyle\s+hidden/i.test(text) ? "danger" : "warning";
      if (/hash/.test(normalized) || /\b[a-f0-9]{32,}\b/i.test(text)) return "warning";
      if (/source_ip|dest_ip|source_port|dest_port/.test(normalized) || /(?:\d{1,3}\.){3}\d{1,3}|https?:\/\//i.test(text)) return "info";
      if (/file|registry|service|process|parent_process/.test(normalized)) return "accent";
      if (/user|domain|host|computer/.test(normalized)) return "identity";
      if (/event_id|level|channel|provider|category/.test(normalized)) return "event";
      return "normal";
    },
    commandFragments(value) {
      return String(value)
        .split(/(\s+)/)
        .filter((part) => part.length > 0)
        .map((part) => ({
          text: part,
          html: this.highlightText(part),
          className: this.commandTokenClass(part),
        }));
    },
    commandTokenClass(token) {
      const clean = String(token).replace(/^["']|["']$/g, "");
      if (/^\s+$/.test(token)) return "";
      if (/(encodedcommand|executionpolicy|bypass|hidden|downloadstring|frombase64string|invoke-expression|\biex\b|nop|noprofile)/i.test(clean)) {
        return "cmd-alert";
      }
      if (/^[-/][a-z0-9_-]+$/i.test(clean)) return "cmd-switch";
      if (/https?:\/\/\S+/i.test(clean)) return "cmd-url";
      if (/^(?:\d{1,3}\.){3}\d{1,3}(?::\d+)?$/.test(clean)) return "cmd-ip";
      if (/^[a-f0-9]{32,}$/i.test(clean)) return "cmd-hash";
      if (/[a-z]:\\|\\\\|\.ps1\b|\.exe\b|\.dll\b|\.bat\b|\.cmd\b/i.test(clean)) return "cmd-path";
      return "";
    },
    addToast(message, type) {
      const id = Date.now() + Math.random();
      this.toasts.push({ id, message, type: type || 'info' });
      setTimeout(() => {
        this.toasts = this.toasts.filter(t => t.id !== id);
      }, 3000);
    },
    renderMarkdown(text) {
      if (!text) return '';
      const safe = this.escapeHtml(text);
      return safe
        .replace(/^### (.+)$/gm, '<h3>$1</h3>')
        .replace(/^## (.+)$/gm, '<h2>$1</h2>')
        .replace(/^# (.+)$/gm, '<h1>$1</h1>')
        .replace(/\*\*(.+?)\*\*/g, '<strong>$1</strong>')
        .replace(/\*(.+?)\*/g, '<em>$1</em>')
        .replace(/`(.+?)`/g, '<code>$1</code>')
        .replace(/^- (.+)$/gm, '<li>$1</li>')
        .replace(/(<li>.*<\/li>\n?)+/g, '<ul>$&</ul>')
        .replace(/\n{2,}/g, '</p><p>')
        .replace(/\n/g, '<br>')
        .replace(/^(?!<[hul])/m, '');
    },
    iocTypeStyle(type) {
      const colors = { ip: '#38bdf8', domain: '#22d3ee', url: '#67e8f9', hash: '#fb7185', email: '#f472b6', file: '#fb923c', registry: '#c084fc', process: '#facc15' };
      const c = colors[String(type).toLowerCase()] || '#64748b';
      return { '--raw-color': c, background: c + '22', color: '#fff' };
    },
    copyText(value) {
      const text = String(value || "");
      if (!text) return;
      if (navigator.clipboard && navigator.clipboard.writeText) {
        navigator.clipboard.writeText(text).catch(() => {});
      }
    },
    truncate(text, maxLen) {
      if (!text) return '';
      const s = String(text);
      return s.length > maxLen ? s.slice(0, maxLen) + '…' : s;
    },
    rowNumber(index) {
      return (this.page - 1) * this.limit + index + 1;
    },
    toggleSelect(eventId) {},
    toggleSelectAll() {},
    bulkBookmark() {},
    toggleSummary(eventId) {
      this.expandedSummary = this.expandedSummary === eventId ? null : eventId;
    },

    // ── FIXED: Ctrl+AltGraph+/ for Indian keyboard layout ──
    // AltGraph on Windows fires ctrlKey=true, so key="/" + ctrlKey=true matches perfectly.
    // Also handles standard Alt+/ and macOS ÷ as fallbacks.
    onKeyDown(event) {
      if (event.key === "Escape" && this.upload.modalOpen) {
        event.preventDefault();
        if (!this.upload.locked) {
          this.closeUploadModal();
        }
        return;
      }

      const isSearchShortcut =
        (event.key === "/" && event.ctrlKey && !event.shiftKey && !event.metaKey) ||
        (event.key === "/" && event.altKey && !event.shiftKey && !event.metaKey) ||
        (event.key === "\u00F7" && !event.shiftKey && !event.metaKey);
      if (isSearchShortcut) {
        event.preventDefault();
        const searchInput = document.querySelector('input[placeholder="Search text"]');
        if (searchInput) {
          searchInput.focus();
          searchInput.select();
        }
        return;
      }
      if (event.key === "Escape" && this.eventDetail) {
        event.preventDefault();
        this.closeEvent();
        return;
      }
      if (!this.eventDetail || !this.events.length) return;
      const active = document.activeElement;
      if (
        active && (
          active.tagName === "INPUT" ||
          active.tagName === "TEXTAREA" ||
          active.tagName === "SELECT" ||
          active.isContentEditable
        )
      ) return;
      if (event.key === "ArrowDown") {
        event.preventDefault();
        this.stepSelection(1);
      } else if (event.key === "ArrowUp") {
        event.preventDefault();
        this.stepSelection(-1);
      }
    },

    stepSelection(delta) {
      if (this.selectedEventIndex < 0) return;
      const t0 = performance.now();
      this.detailHeight = this.clampDetailHeight(this.detailHeight);
      const next = this.selectedEventIndex + delta;
      if (next >= 0 && next < this.events.length) {
        this.selectedEventId = this.events[next].id;
        this.selectedEventIndex = next;
        const t1 = performance.now();
        if (t1 - t0 > 10) console.warn(`stepSelection sync took ${(t1-t0).toFixed(1)}ms`);
        this._debounceDetailFetch(this.events[next].id);
        return;
      }
      if (this._navAbortController) this._navAbortController.abort();
      this._navAbortController = new AbortController();
      const signal = this._navAbortController.signal;
      if (delta > 0 && this.page < this.totalPages) {
        this.page += 1;
        this._loadAndSelect(delta, signal);
      } else if (delta < 0 && this.page > 1) {
        this.page -= 1;
        this._loadAndSelect(delta, signal);
      }
    },
    async _loadAndSelect(delta, signal) {
      await this.loadEvents({ preserveDetail: true });
      if (signal.aborted || !this.events.length) return;
      const idx = delta > 0 ? 0 : this.events.length - 1;
      const evt = this.events[idx];
      this.selectedEventId = evt.id;
      this.selectedEventIndex = idx;
      this._debounceDetailFetch(evt.id);
    },
    _selectAndFetch(id, index, signal) {
      this.selectedEventId = id;
      this.selectedEventIndex = index;
      this.detailHeight = this.clampDetailHeight(this.detailHeight);
      this._fetchDetail(id, signal);
    },
    async _fetchDetail(id, signal) {
      const t0 = performance.now();
      try {
        const res = await fetch(`/api/investigations/${this.selectedId}/events/${id}`, { signal });
        if (!res.ok) return;
        const detail = await res.json();
        const t1 = performance.now();
        if (!signal.aborted && this.selectedEventId === id) {
          if (t1 - t0 > 50) console.warn(`fetchDetail: ${(t1-t0).toFixed(0)}ms net, ${((t1-t0)*1000|0)/1000}s`);
          this.eventDetail = detail;
          Vue.nextTick(() => {
            console.log(`  → re-render complete: ${(performance.now()-t1).toFixed(1)}ms`);
          });
        }
      } catch (err) {
        if (err.name === 'AbortError') return;
        console.error('fetchDetail error:', err);
      }
    },
    _debounceDetailFetch(id) {
      if (this._fetchingNav) {
        this._pendingNavId = id;
        return;
      }
      this._fetchingNav = true;
      this._pendingNavId = null;
      if (this._navAbortController) this._navAbortController.abort();
      this._navAbortController = new AbortController();
      this._fetchDetail(id, this._navAbortController.signal).finally(() => {
        this._fetchingNav = false;
        if (this._pendingNavId) {
          const next = this._pendingNavId;
          this._pendingNavId = null;
          this._debounceDetailFetch(next);
        }
      });
    },
    _buildFieldCache(detail) {
      const rows = [];
      const source = detail.raw_data;
      let parsed = null;
      if (typeof source === 'string' && source.trim()) {
        try { parsed = JSON.parse(source.trim()); } catch (e) { parsed = source.trim(); }
      } else if (source && typeof source === 'object') {
        parsed = source;
      }
      if (!parsed) {
        parsed = {};
        Object.entries(detail).forEach(([k, v]) => {
          if (k === 'raw_data' || this.isEmptyDetailValue(v)) return;
          parsed[k] = v;
        });
      }
      this.flattenRawValue(parsed, '', rows);
      const formattedRows = rows
        .filter((r) => !this.isHeaderRawField(r))
        .map((r, i) => ({
          ...r,
          id: i + '-' + r.path,
          originalIndex: i,
          displayPath: this.formatRawPath(r.path),
          category: this.rawFieldCategory(r.path),
          priority: this.rawFieldPriority(r.path),
          valueRank: this.rawValueRank(r),
          empty: this.rawValueRank(r) > 0,
        }))
        .sort((a, b) => {
          if (a.valueRank !== b.valueRank) return a.valueRank - b.valueRank;
          if (a.priority !== b.priority) return a.priority - b.priority;
          return a.originalIndex - b.originalIndex;
        });
      if (!this.isEmptyDetailValue(detail.description)) {
        formattedRows.unshift({ id: 'summary-row', originalIndex: -1, path: 'Event.Summary', displayPath: 'Event / Summary', category: 'event', priority: -1, type: 'string', valueRank: 0, empty: false, displayValue: this.formatDetailValue(detail.description) });
      }
      const groups = {};
      const order = ['time','event','identity','command','process','network','port','hash','file','registry','security','service','guid','data','other'];
      formattedRows.forEach((r) => {
        const cat = r.category || 'other';
        if (!groups[cat]) groups[cat] = { category: cat, items: [] };
        groups[cat].items.push(r);
      });
      const grouped = order.filter((c) => groups[c]).map((c) => groups[c]);
      return { rows: formattedRows, groups: grouped };
    },
    startResize(event) {
      event.preventDefault();
      this.resizing = true;
      this.resizeStartY = event.clientY;
      this.resizeStartHeight = this.detailHeight;
      window.addEventListener("mousemove", this.boundResizeMove);
      window.addEventListener("mouseup", this.boundResizeStop);
    },
    handleResizeMove(event) {
      if (!this.resizing) return;
      const delta = this.resizeStartY - event.clientY;
      this.detailHeight = this.clampDetailHeight(this.resizeStartHeight + delta);
    },
    stopResize() {
      if (!this.resizing) return;
      this.resizing = false;
      if (this.boundResizeMove) {
        window.removeEventListener("mousemove", this.boundResizeMove);
      }
      if (this.boundResizeStop) {
        window.removeEventListener("mouseup", this.boundResizeStop);
      }
    },
    getDetailMaxHeight() {
      const topbarHeight = 64;
      return Math.round(window.innerHeight - topbarHeight);
    },
    getDefaultDetailHeight() {
      return Math.round(window.innerHeight * 0.4);
    },
    clampDetailHeight(height) {
      const minHeight = 180;
      return Math.min(this.getDetailMaxHeight(), Math.max(minHeight, height));
    },
    onWindowResize() {
      if (!this.eventDetail) return;
      this.detailHeight = this.clampDetailHeight(this.detailHeight);
    },
    onSelectKeydown(fieldName, event) {
      if (event.key === "Enter") {
        event.preventDefault();
        this.applyFilters();
        return;
      }
      if (event.key.length === 1 && !event.ctrlKey && !event.metaKey && !event.altKey) {
        const select = event.target;
        const options = Array.from(select.options);
        const typed = event.key.toLowerCase();
        const currentIndex = select.selectedIndex;
        for (let i = 1; i < options.length; i++) {
          const idx = (currentIndex + i) % options.length;
          const text = options[idx].text.toLowerCase();
          if (text.startsWith(typed)) {
            select.selectedIndex = idx;
            this.filters[fieldName] = options[idx].value;
            break;
          }
        }
      }
    },
    normalizeTimeFilter(value) {
      const raw = String(value).trim();
      if (!raw) return "";
      if (!/^\d{4}-\d{2}-\d{2}/.test(raw)) {
        return "";
      }
      return raw.replace(/\s+/g, " ");
    },
    relativeTime(ts) {
      if (!ts) return "";
      const diff = Date.now() - new Date(ts).getTime();
      const units = [
        [31536000, "year"],
        [2592000, "month"],
        [86400, "day"],
        [3600, "hour"],
        [60, "minute"],
      ];
      for (const [sec, label] of units) {
        const n = Math.floor(diff / (sec * 1000));
        if (n >= 1) return `${n} ${label}${n > 1 ? "s" : ""} ago`;
      }
      return "just now";
    },
  },
}).mount("#app");
