import math
import re

from binaryninja import BinaryView, core_ui_enabled, log_error
from binaryninja.enums import SettingsScope
from binaryninja.plugin import BackgroundTaskThread
from binaryninja.settings import Settings

from .ropninja import (
    PLUGIN_NAME,
    SETTING_AUTO_FIND_ON_OPEN,
    SETTING_DEDUPLICATE_GADGETS,
    SETTING_INCLUDE_BRANCHES,
    SETTING_INCLUDE_LEAVE,
    SETTING_MAX_PREVIOUS_BYTES,
    SETTING_STRIP_ADDRESS_ZEROS,
    find_rop_gadgets_in_view,
    format_gadget_rows_for_display,
    get_auto_find_on_open,
    get_deduplicate_gadgets,
    get_include_branches,
    get_include_leave,
    get_max_previous_bytes,
    get_strip_address_zeros,
    register_plugin_settings,
)


register_plugin_settings()


if core_ui_enabled():
    try:
        from binaryninjaui import (
            Sidebar,
            SidebarContextSensitivity,
            SidebarWidget,
            SidebarWidgetLocation,
            SidebarWidgetType,
            UIContext,
            UIActionHandler,
            WidgetPane,
            getMonospaceFont,
            getTokenColor,
        )
        from PySide6.QtCore import QObject, QPointF, QRectF, QSize, Qt, QTimer, Signal
        from PySide6.QtGui import QColor, QFont, QIcon, QImage, QPainter, QPen, QPixmap
        from PySide6.QtWidgets import (
            QAbstractItemView,
            QCheckBox,
            QComboBox,
            QDialog,
            QFormLayout,
            QHBoxLayout,
            QHeaderView,
            QLabel,
            QLineEdit,
            QPushButton,
            QApplication,
            QStyle,
            QStyledItemDelegate,
            QStyleOptionViewItem,
            QTableView,
            QSpinBox,
            QTableWidget,
            QTableWidgetItem,
            QVBoxLayout,
            QWidget,
        )

        TOKEN_FRAGMENTS_ROLE = 0x0101
        _settings_dialog = None


        def make_settings_icon() -> QIcon:
            image = QImage(24, 24, QImage.Format_ARGB32)
            image.fill(0)

            painter = QPainter()
            painter.begin(image)
            painter.setRenderHint(QPainter.RenderHint.Antialiasing)

            color = QColor(235, 235, 235, 255)
            painter.setPen(QPen(color, 2, Qt.PenStyle.SolidLine, Qt.PenCapStyle.RoundCap))
            center = QPointF(12, 12)
            for index in range(8):
                angle = (math.pi * 2 * index) / 8
                inner = QPointF(center.x() + math.cos(angle) * 6, center.y() + math.sin(angle) * 6)
                outer = QPointF(center.x() + math.cos(angle) * 9, center.y() + math.sin(angle) * 9)
                painter.drawLine(inner, outer)

            painter.setPen(QPen(color, 2, Qt.PenStyle.SolidLine, Qt.PenCapStyle.RoundCap))
            painter.drawEllipse(QRectF(6.5, 6.5, 11, 11))
            painter.drawEllipse(QRectF(10, 10, 4, 4))
            painter.end()
            return QIcon(QPixmap.fromImage(image))


        class BinjaRopSettingsDialog(QDialog):
            settings_saved = Signal()

            def __init__(self, parent=None):
                super().__init__(parent)
                self.setWindowTitle(f"{PLUGIN_NAME} Settings")
                self.setWindowFlags(self.windowFlags() & ~Qt.WindowContextHelpButtonHint)

                self.max_previous_bytes = QSpinBox(self)
                self.max_previous_bytes.setRange(1, 256)
                self.max_previous_bytes.setSuffix(" bytes")

                self.deduplicate_gadgets = QCheckBox("Deduplicate gadgets", self)
                self.auto_find_on_open = QCheckBox("Auto-find when UI opens", self)
                self.include_branches = QCheckBox("Include jump gadgets", self)
                self.include_leave = QCheckBox("Include leave gadgets", self)
                self.strip_address_zeros = QCheckBox("Strip leading address zeros", self)

                form = QFormLayout()
                form.addRow("Maximum gadget backtrack", self.max_previous_bytes)
                form.addRow("", self.deduplicate_gadgets)
                form.addRow("", self.auto_find_on_open)
                form.addRow("", self.include_branches)
                form.addRow("", self.include_leave)
                form.addRow("", self.strip_address_zeros)

                self.save_button = QPushButton("&Save", self)
                self.close_button = QPushButton("Close", self)
                self.save_button.clicked.connect(self.save_settings)
                self.close_button.clicked.connect(self.close)

                buttons = QHBoxLayout()
                buttons.addStretch()
                buttons.addWidget(self.save_button)
                buttons.addWidget(self.close_button)

                layout = QVBoxLayout()
                layout.addLayout(form)
                layout.addLayout(buttons)
                self.setLayout(layout)
                self.load_settings()

            def load_settings(self) -> None:
                self.max_previous_bytes.setValue(get_max_previous_bytes())
                self.deduplicate_gadgets.setChecked(get_deduplicate_gadgets())
                self.auto_find_on_open.setChecked(get_auto_find_on_open())
                self.include_branches.setChecked(get_include_branches())
                self.include_leave.setChecked(get_include_leave())
                self.strip_address_zeros.setChecked(get_strip_address_zeros())

            def save_settings(self) -> None:
                settings = Settings()
                settings.set_integer(
                    SETTING_MAX_PREVIOUS_BYTES,
                    self.max_previous_bytes.value(),
                    scope=SettingsScope.SettingsUserScope,
                )
                settings.set_bool(
                    SETTING_DEDUPLICATE_GADGETS,
                    self.deduplicate_gadgets.isChecked(),
                    scope=SettingsScope.SettingsUserScope,
                )
                settings.set_bool(
                    SETTING_AUTO_FIND_ON_OPEN,
                    self.auto_find_on_open.isChecked(),
                    scope=SettingsScope.SettingsUserScope,
                )
                settings.set_bool(
                    SETTING_INCLUDE_BRANCHES,
                    self.include_branches.isChecked(),
                    scope=SettingsScope.SettingsUserScope,
                )
                settings.set_bool(
                    SETTING_INCLUDE_LEAVE,
                    self.include_leave.isChecked(),
                    scope=SettingsScope.SettingsUserScope,
                )
                settings.set_bool(
                    SETTING_STRIP_ADDRESS_ZEROS,
                    self.strip_address_zeros.isChecked(),
                    scope=SettingsScope.SettingsUserScope,
                )
                self.settings_saved.emit()
                self.close()


        def open_settings(on_saved=None) -> None:
            global _settings_dialog
            if _settings_dialog is None:
                _settings_dialog = BinjaRopSettingsDialog()
            if on_saved is not None:
                try:
                    _settings_dialog.settings_saved.disconnect(on_saved)
                except Exception:
                    pass
                _settings_dialog.settings_saved.connect(on_saved)
            _settings_dialog.load_settings()
            _settings_dialog.show()
            _settings_dialog.raise_()
            _settings_dialog.activateWindow()


        class RopSearchSignals(QObject):
            finished = Signal(object)
            failed = Signal(str)


        class RopSearchTask(BackgroundTaskThread):
            def __init__(self, bv: BinaryView):
                super().__init__("", True)
                self.bv = bv
                self.signals = RopSearchSignals()
                self.progress = "[+] ROPNinja: searching for rop gadgets"

            def run(self) -> None:
                try:
                    gadgets = find_rop_gadgets_in_view(self.bv, should_cancel=lambda: self.cancelled)
                    self.signals.finished.emit(gadgets)
                except Exception as exc:
                    log_error(f"ROPNinja: sidebar search failed: {exc}")
                    self.signals.failed.emit(str(exc))
                finally:
                    self.progress = ""


        class GadgetTokenDelegate(QStyledItemDelegate):
            def paint(self, painter, option, index) -> None:
                fragments = index.data(TOKEN_FRAGMENTS_ROLE)
                if not fragments:
                    super().paint(painter, option, index)
                    return

                opt = QStyleOptionViewItem(option)
                self.initStyleOption(opt, index)
                opt.text = ""

                widget = opt.widget
                style = widget.style() if widget is not None else QApplication.style()
                painter.save()
                style.drawControl(QStyle.ControlElement.CE_ItemViewItem, opt, painter, widget)

                rect = style.subElementRect(QStyle.SubElement.SE_ItemViewItemText, opt, widget)
                metrics = opt.fontMetrics
                x = rect.x() + 6
                y = rect.y() + (rect.height() + metrics.ascent() - metrics.descent()) / 2
                selected = bool(option.state & QStyle.StateFlag.State_Selected)
                frame = UIContext.currentViewFrameForWidget(widget) if widget is not None else None

                for token_type, text in fragments:
                    if selected:
                        color = opt.palette.highlightedText().color()
                    else:
                        color = self.token_color(frame, token_type, opt.palette.text().color())
                    painter.setPen(color)
                    painter.drawText(QPointF(x, y), text)
                    x += metrics.horizontalAdvance(text)
                    if x > rect.right():
                        break

                painter.restore()

            @staticmethod
            def token_color(frame, token_type, fallback):
                if frame is None:
                    return fallback
                try:
                    color = getTokenColor(frame, token_type)
                    if color is not None and color.isValid():
                        return color
                except Exception:
                    pass
                return fallback


        class AddressTableWidgetItem(QTableWidgetItem):
            def __lt__(self, other):
                left = self.data(Qt.ItemDataRole.UserRole)
                right = other.data(Qt.ItemDataRole.UserRole)
                if left is not None and right is not None:
                    return left < right
                return super().__lt__(other)


        class RopTableWidget(QTableWidget):
            def __init__(self, *args):
                super().__init__(*args)
                self.resize_callback = None

            def keyPressEvent(self, event) -> None:
                copy_modifiers = Qt.KeyboardModifier.ControlModifier | Qt.KeyboardModifier.MetaModifier
                if event.key() == Qt.Key.Key_C and event.modifiers() & copy_modifiers:
                    self.copy_selected_addresses()
                    return
                super().keyPressEvent(event)

            def resizeEvent(self, event) -> None:
                super().resizeEvent(event)
                if self.resize_callback is not None:
                    self.resize_callback()

            def copy_selected_addresses(self) -> None:
                rows = sorted({index.row() for index in self.selectionModel().selectedRows()})
                if not rows:
                    rows = sorted({index.row() for index in self.selectedIndexes()})
                if not rows:
                    return

                addresses = []
                for row in rows:
                    item = self.item(row, 0)
                    if item is not None:
                        addresses.append(item.text())

                if addresses:
                    QApplication.clipboard().setText("\n".join(addresses))


        class BinjaRopPanel(QWidget):
            def __init__(self, data: BinaryView | None, frame=None, parent=None):
                super().__init__(parent)
                self.data = data
                self.frame = frame
                self.rows = []
                self.task = None
                self.search_data = None
                self.result_data = None
                self.auto_find_views = []
                self.strip_address_zeros = get_strip_address_zeros()

                self.find_button = QPushButton("Find", self)
                self.find_button.clicked.connect(self.start_search)

                self.settings_button = QPushButton(self)
                self.settings_button.setIcon(make_settings_icon())
                self.settings_button.setIconSize(QSize(18, 18))
                self.settings_button.setToolTip("Settings")
                self.settings_button.setFixedWidth(30)
                self.settings_button.clicked.connect(self.open_settings)

                self.category_filter = QComboBox(self)
                self.category_filter.setMinimumWidth(128)
                self.category_filter.addItem("All gadgets", "all")
                self.category_filter.addItem("Pop gadgets", "pop")
                self.category_filter.addItem("Move gadgets", "mov")
                self.category_filter.addItem("Call gadgets", "call")
                self.category_filter.addItem("Stack pivots", "stack")
                self.category_filter.addItem("Branches", "branch")
                self.category_filter.addItem("Leave", "leave")
                self.category_filter.currentIndexChanged.connect(lambda _: self.apply_filter())

                self.filter = QLineEdit(self)
                self.filter.setPlaceholderText("Filter gadgets")
                self.filter.textChanged.connect(lambda _: self.apply_filter())

                controls_layout = QHBoxLayout()
                controls_layout.setContentsMargins(0, 0, 0, 0)
                controls_layout.addWidget(self.find_button)
                controls_layout.addWidget(self.category_filter, 1)
                controls_layout.addWidget(self.settings_button)

                self.status = QLabel("Ready", self)

                self.table = RopTableWidget(0, 2, self)
                self.table.resize_callback = self.update_frozen_table_geometry
                self.table.setFont(getMonospaceFont(self))
                self.table.setHorizontalHeaderLabels(["Address", "Gadget"])
                self.table.verticalHeader().hide()
                self.table.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
                self.table.setSelectionMode(QAbstractItemView.SelectionMode.ExtendedSelection)
                self.table.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
                self.table.setSortingEnabled(True)
                self.table.setAlternatingRowColors(True)
                self.table.setStyleSheet("QTableView::item { padding-left: 4px; padding-right: 10px; }")
                self.table.setHorizontalScrollMode(QAbstractItemView.ScrollMode.ScrollPerPixel)
                self.table.setHorizontalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAsNeeded)
                self.table.horizontalHeader().setSectionResizeMode(0, QHeaderView.ResizeMode.Fixed)
                self.table.horizontalHeader().setSectionResizeMode(1, QHeaderView.ResizeMode.Interactive)
                self.table.horizontalHeader().setStretchLastSection(False)
                self.table.setColumnHidden(0, True)
                self.table.itemDoubleClicked.connect(self.navigate_to_item)
                self.table.setItemDelegateForColumn(1, GadgetTokenDelegate(self.table))

                self.frozen_table = QTableView(self.table)
                self.frozen_table.setModel(self.table.model())
                self.frozen_table.setSelectionModel(self.table.selectionModel())
                self.frozen_table.setFont(self.table.font())
                self.frozen_table.setFocusPolicy(Qt.FocusPolicy.NoFocus)
                self.frozen_table.setAlternatingRowColors(True)
                self.frozen_table.setStyleSheet(self.table.styleSheet())
                self.frozen_table.verticalHeader().hide()
                self.frozen_table.horizontalHeader().setSectionResizeMode(0, QHeaderView.ResizeMode.Fixed)
                self.frozen_table.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
                self.frozen_table.setColumnHidden(1, True)
                self.frozen_table.setHorizontalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAlwaysOff)
                self.frozen_table.setVerticalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAlwaysOff)
                self.frozen_table.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
                self.frozen_table.setSelectionMode(QAbstractItemView.SelectionMode.ExtendedSelection)
                self.frozen_table.doubleClicked.connect(self.navigate_to_index)
                self.table.verticalScrollBar().valueChanged.connect(self.frozen_table.verticalScrollBar().setValue)
                self.frozen_table.verticalScrollBar().valueChanged.connect(self.table.verticalScrollBar().setValue)
                self.table.viewport().stackUnder(self.frozen_table)
                self.frozen_table.show()

                layout = QVBoxLayout()
                layout.setContentsMargins(6, 6, 6, 6)
                layout.addWidget(self.filter)
                layout.addLayout(controls_layout)
                layout.addWidget(self.table, 1)
                layout.addWidget(self.status)
                self.setLayout(layout)

                self.refresh_context()

            def showEvent(self, event) -> None:
                super().showEvent(event)
                self.maybe_start_auto_find()

            def open_settings(self) -> None:
                open_settings(self.settings_changed)

            def settings_changed(self) -> None:
                self.strip_address_zeros = get_strip_address_zeros()
                data = self.resolve_data()
                self.update_find_button(data)
                if self.rows:
                    self.apply_filter()
                elif data is None:
                    self.status.setText("Open a BinaryView to search for ROP gadgets.")
                else:
                    filename = getattr(getattr(data, "file", None), "filename", "")
                    self.status.setText(f"Ready: {filename}" if filename else "Ready")
                self.maybe_start_auto_find()

            def set_view_frame(self, frame) -> None:
                self.frame = frame
                self.refresh_context()

            @staticmethod
            def same_data(left, right) -> bool:
                if left is None or right is None:
                    return left is right
                if left is right:
                    return True
                try:
                    return left.handle == right.handle
                except Exception:
                    return False

            def resolve_data(self):
                candidates = []
                if self.frame is not None:
                    candidates.append(self.frame)

                current_frame = UIContext.currentViewFrameForWidget(self)
                if current_frame is not None and current_frame not in candidates:
                    candidates.append(current_frame)

                for frame in candidates:
                    try:
                        data = frame.getCurrentBinaryView()
                    except Exception:
                        data = None

                    if data is None:
                        try:
                            view = frame.getCurrentViewInterface()
                            data = view.getData() if view is not None else None
                        except Exception:
                            data = None

                    if data is not None:
                        self.data = data
                        self.frame = frame
                        return data

                return self.data

            def refresh_context(self) -> None:
                data = self.resolve_data()
                self.update_find_button(data)
                if self.result_data is not None and not self.same_data(data, self.result_data):
                    self.rows = []
                    self.result_data = None
                    self.populate_table([])

                if data is None:
                    self.status.setText("Open a BinaryView to search for ROP gadgets.")
                elif not self.rows:
                    filename = getattr(getattr(data, "file", None), "filename", "")
                    self.status.setText(f"Ready: {filename}" if filename else "Ready")
                self.maybe_start_auto_find()

            def auto_find_seen_data(self, data) -> bool:
                return any(self.same_data(data, seen_data) for seen_data in self.auto_find_views)

            def maybe_start_auto_find(self) -> None:
                if not self.isVisible() or not get_auto_find_on_open():
                    return

                data = self.resolve_data()
                if data is None or self.task is not None:
                    return
                if self.result_data is not None and self.same_data(data, self.result_data):
                    return
                if self.auto_find_seen_data(data):
                    return

                self.auto_find_views.append(data)
                QTimer.singleShot(0, self.start_search)

            def update_find_button(self, data=None) -> None:
                if data is None:
                    data = self.resolve_data()
                auto_find = get_auto_find_on_open()
                self.find_button.setVisible(not auto_find)
                self.find_button.setEnabled(not auto_find and data is not None and self.task is None)

            def start_search(self) -> None:
                data = self.resolve_data()
                if data is None:
                    self.update_find_button(data)
                    self.status.setText("Open a BinaryView to search for ROP gadgets.")
                    return

                self.find_button.setEnabled(False)
                self.status.setText("Searching...")
                self.rows = []
                self.search_data = data
                self.result_data = None
                self.populate_table([])

                self.task = RopSearchTask(data)
                self.update_find_button(data)
                self.task.signals.finished.connect(self.search_finished)
                self.task.signals.failed.connect(self.search_failed)
                self.task.start()

            def search_finished(self, gadgets: dict[int, object]) -> None:
                finished_data = self.search_data
                current_data = self.resolve_data()
                if finished_data is not None and not self.same_data(current_data, finished_data):
                    self.rows = []
                    self.result_data = None
                    self.search_data = None
                    self.populate_table([])
                    self.task = None
                    self.refresh_context()
                    return

                self.result_data = finished_data
                self.rows = format_gadget_rows_for_display(self.result_data, gadgets) if self.result_data is not None else []
                self.apply_filter()
                self.task = None
                self.update_find_button(current_data)

            def search_failed(self, message: str) -> None:
                self.search_data = None
                self.result_data = None
                self.task = None
                self.update_find_button(self.resolve_data())
                self.status.setText(f"Search failed: {message}")

            def apply_filter(self) -> None:
                query = self.filter.text().strip().lower()
                category = self.category_filter.currentData()
                rows = [row for row in self.rows if self.matches_category(row, category)]

                if not query:
                    self.populate_table(rows)
                    if len(rows) == len(self.rows):
                        self.status.setText(f"{len(self.rows)} gadgets")
                    else:
                        self.status.setText(f"{len(rows)} of {len(self.rows)} gadgets")
                    return

                filtered = [
                    row
                    for row in rows
                    if query in f"0x{row.address:x}".lower() or query in row.text.lower()
                ]
                self.populate_table(filtered)
                self.status.setText(f"{len(filtered)} of {len(self.rows)} gadgets")

            @staticmethod
            def matches_category(row, category) -> bool:
                text = row.text.lower()
                if category == "pop":
                    return re.search(r"\bpop\b", text) is not None
                if category == "mov":
                    return re.search(r"\bmov\b", text) is not None
                if category == "call":
                    return re.search(r"\bcall\b", text) is not None
                if category == "stack":
                    return re.search(r"\b(leave|pop\s+rsp|xchg\s+rsp|mov\s+rsp|add\s+rsp|sub\s+rsp)\b", text) is not None
                if category == "branch":
                    return re.search(r"\bj[a-z]*\b", text) is not None
                if category == "leave":
                    return re.search(r"\bleave\b", text) is not None
                return True

            def populate_table(self, rows) -> None:
                self.table.setSortingEnabled(False)
                self.table.setRowCount(len(rows))
                max_gadget_width = self.table.viewport().width()
                max_address_width = self.table.fontMetrics().horizontalAdvance("Address") + 28
                for row_index, row in enumerate(rows):
                    formatted_address = self.format_address(row.address)
                    addr_item = AddressTableWidgetItem(formatted_address)
                    addr_item.setData(Qt.ItemDataRole.UserRole, row.address)
                    gadget_item = QTableWidgetItem(row.text)
                    gadget_item.setData(TOKEN_FRAGMENTS_ROLE, row.fragments)
                    self.table.setItem(row_index, 0, addr_item)
                    self.table.setItem(row_index, 1, gadget_item)
                    max_address_width = max(
                        max_address_width,
                        self.table.fontMetrics().horizontalAdvance(formatted_address) + 28,
                    )
                    max_gadget_width = max(
                        max_gadget_width,
                        self.table.fontMetrics().horizontalAdvance(row.text) + 48,
                    )

                self.table.setColumnWidth(0, max_address_width)
                self.frozen_table.setColumnWidth(0, max_address_width)
                self.table.setColumnWidth(1, max_gadget_width)
                self.update_frozen_table_geometry()
                self.table.setSortingEnabled(True)

            def update_frozen_table_geometry(self) -> None:
                if not hasattr(self, "frozen_table"):
                    return

                frozen_width = self.frozen_table.columnWidth(0) + self.frozen_table.frameWidth() * 2
                self.table.setViewportMargins(frozen_width, 0, 0, 0)
                self.frozen_table.setGeometry(
                    self.table.frameWidth(),
                    self.table.frameWidth(),
                    frozen_width,
                    self.table.viewport().height() + self.table.horizontalHeader().height(),
                )

            def format_address(self, addr: int) -> str:
                if self.strip_address_zeros:
                    return f"0x{addr:x}"
                return f"0x{addr:016x}"

            def navigate_to_item(self, item: QTableWidgetItem) -> None:
                self.navigate_to_row(item.row())

            def navigate_to_index(self, index) -> None:
                self.navigate_to_row(index.row())

            def navigate_to_row(self, row: int) -> None:
                addr_item = self.table.item(row, 0)
                if addr_item is None:
                    return

                addr = addr_item.data(Qt.ItemDataRole.UserRole)
                if addr is None:
                    return

                frame = self.frame if hasattr(self.frame, "getCurrentDataType") else UIContext.currentViewFrameForWidget(self)
                if frame is not None and hasattr(frame, "getCurrentDataType"):
                    view_type = frame.getCurrentDataType()
                    if frame.navigate(f"Linear:{view_type}", addr):
                        return
                    frame.navigate(f"Graph:{view_type}", addr)
                    return

                if self.data is not None:
                    self.data.navigate(f"Linear:{self.data.view_type}", addr)

        class BinjaRopSidebarWidget(SidebarWidget):
            def __init__(self, name, frame, data):
                SidebarWidget.__init__(self, name)
                self.action_handler = UIActionHandler()
                self.action_handler.setupActionHandler(self)
                self.panel = BinjaRopPanel(data, frame, self)

                layout = QVBoxLayout()
                layout.setContentsMargins(0, 0, 0, 0)
                layout.addWidget(self.panel)
                self.setLayout(layout)

            def contextMenuEvent(self, event) -> None:
                self.m_contextMenuManager.show(self.m_menu, self.action_handler)

            def notifyViewChanged(self, view_frame) -> None:
                self.panel.set_view_frame(view_frame)


        class BinjaRopSidebarWidgetType(SidebarWidgetType):
            def __init__(self):
                icon = QImage(56, 56, QImage.Format_RGB32)
                icon.fill(0)

                painter = QPainter()
                painter.begin(icon)
                painter.setRenderHint(QPainter.RenderHint.Antialiasing)

                white = QColor(255, 255, 255, 255)
                painter.setPen(QPen(white, 4, Qt.PenStyle.SolidLine, Qt.PenCapStyle.RoundCap, Qt.PenJoinStyle.RoundJoin))
                painter.drawEllipse(QRectF(8, 8, 15, 15))
                painter.drawEllipse(QRectF(33, 8, 15, 15))
                painter.drawLine(QPointF(22, 15.5), QPointF(34, 15.5))

                painter.setPen(QPen(white, 3, Qt.PenStyle.SolidLine, Qt.PenCapStyle.RoundCap, Qt.PenJoinStyle.RoundJoin))
                painter.drawLine(QPointF(16, 25), QPointF(16, 35))
                painter.drawLine(QPointF(16, 35), QPointF(39, 35))
                painter.drawLine(QPointF(39, 35), QPointF(39, 27))
                painter.drawLine(QPointF(39, 27), QPointF(34, 32))
                painter.drawLine(QPointF(39, 27), QPointF(44, 32))

                painter.setFont(QFont("Open Sans", 12, QFont.Weight.Bold))
                painter.setPen(white)
                painter.drawText(QRectF(0, 34, 56, 20), Qt.AlignCenter, "ROP")
                painter.end()

                SidebarWidgetType.__init__(self, icon, PLUGIN_NAME)

            def createWidget(self, frame, data):
                return BinjaRopSidebarWidget(PLUGIN_NAME, frame, data)

            def defaultLocation(self):
                return SidebarWidgetLocation.RightContent

            def contextSensitivity(self):
                return SidebarContextSensitivity.SelfManagedSidebarContext

            def canUseAsPane(self, split_pane_widget, data):
                return True

            def createPane(self, split_pane_widget, data):
                return WidgetPane(BinjaRopPanel(data, split_pane_widget), PLUGIN_NAME)

        Sidebar.addSidebarWidgetType(BinjaRopSidebarWidgetType())

    except Exception as exc:
        log_error(f"ROPNinja: UI initialization failed: {exc}")
