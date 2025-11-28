/*
 * @saoshao<1224165231@qq.com>
 */

package DetSql.model;

import javax.swing.table.AbstractTableModel;
import java.util.ArrayList;
import java.util.List;
import java.util.HashMap;
import java.util.Map;
import java.util.Objects;

//原始请求表格
public class SourceTableModel extends AbstractTableModel {
    // P0-1 修复：添加容量限制,防止长期扫描导致 OOM
    private static final int MAX_LOG_SIZE = 10000;
    
    private final List<SourceLogEntry> log;
    // 新增：myHash -> SourceLogEntry 索引
    private final Map<String, SourceLogEntry> hashIndex;

    public SourceTableModel() {
        this.log = new ArrayList<>();
        this.hashIndex = new HashMap<>();
    }

//    @Override
//    public Class<?> getColumnClass(int columnIndex) {
//        if(columnIndex==0){
//            return Integer.class;
//        }
//        return super.getColumnClass(columnIndex);
//    }

    @Override
    public synchronized int getRowCount() {
        return log.size();
    }

    @Override
    public int getColumnCount() {
        return 7;
    }

    @Override
    public String getColumnName(int column) {
        return switch (column) {
            case 0 -> "#";
            case 1 -> "Tool";
            case 2 -> "Method";
            case 3 -> "Host";
            case 4 -> "URL";
            case 5 -> "BodyLength";
            case 6 -> "VulnState";
            default -> "";
        };
    }

    @Override
    public synchronized Object getValueAt(int rowIndex, int columnIndex) {
        SourceLogEntry logEntry = log.get(rowIndex);
        return switch (columnIndex) {
            case 0 -> logEntry.getId();
            case 1 -> logEntry.getTool();
            case 2 -> logEntry.getMethod();
            case 3 -> logEntry.getHttpService();
            case 4 -> logEntry.getPath();
            case 5 -> logEntry.getBodyLength();
            case 6 -> logEntry.getVulnState();
            default -> "";
        };


    }

    public synchronized void add(SourceLogEntry logEntry) {
        // P0-1 修复：容量检查 - 移除最旧记录
        if (log.size() >= MAX_LOG_SIZE) {
            remove(0);  // 移除最旧的记录 (索引 0)
        }
        
        int index = log.size();
        log.add(logEntry);
        // 维护索引
        if (logEntry != null && logEntry.getMyHash() != null) {
            hashIndex.put(logEntry.getMyHash(), logEntry);
        }
        fireTableRowsInserted(index, index);
    }

    public synchronized void addx(SourceLogEntry logEntry, int index) {
        if (index < log.size()) {
            SourceLogEntry oldEntry = log.get(index);
            if (oldEntry != null && oldEntry.getMyHash() != null) {
                hashIndex.remove(oldEntry.getMyHash());
            }
        }
        log.set(index, logEntry);
        if (logEntry != null && logEntry.getMyHash() != null) {
            hashIndex.put(logEntry.getMyHash(), logEntry);
        }
        fireTableRowsUpdated(index, index);
    }
    /**
     * 更新指定行的漏洞状态（VulnState列）
     * 用于在测试完成后更新表格中的漏洞检测结果
     *
     * @param entry      包含更新数据的日志条目
     * @param modelIndex 模型中的行索引
     */
    public synchronized void updateVulnState(SourceLogEntry entry, int modelIndex) {
        if (modelIndex < log.size()) {
            SourceLogEntry oldEntry = log.get(modelIndex);
            if (oldEntry != null && oldEntry.getMyHash() != null) {
                hashIndex.remove(oldEntry.getMyHash());
            }
        }
        log.set(modelIndex, entry);
        if (entry != null && entry.getMyHash() != null) {
            hashIndex.put(entry.getMyHash(), entry);
        }
        fireTableCellUpdated(modelIndex, 6);
    }

    public synchronized SourceLogEntry get(int rowIndex) {
        return log.get(rowIndex);
    }

    // 新增：通过 myHash 查询原始请求
    public synchronized SourceLogEntry findByHash(String hash) {
        return hashIndex.get(hash);
    }

    // 新增：提供受控 indexOf，基于 equals(id)
    public synchronized int indexOf(SourceLogEntry e) {
        return log.indexOf(e);
    }

    // 新增：根据模型索引删除，并维护索引
    public synchronized void remove(int modelIndex) {
        if (modelIndex >= 0 && modelIndex < log.size()) {
            SourceLogEntry entry = log.remove(modelIndex);
            if (entry != null && entry.getMyHash() != null) {
                // 仅当映射指向当前 entry 时移除，避免误删
                SourceLogEntry mapped = hashIndex.get(entry.getMyHash());
                if (mapped == entry) {
                    hashIndex.remove(entry.getMyHash());
                }
            }
            fireTableRowsDeleted(modelIndex, modelIndex);
        }
    }

    // 新增：清空并重置索引
    public synchronized void clear() {
        log.clear();
        hashIndex.clear();
        fireTableDataChanged();
    }
}
