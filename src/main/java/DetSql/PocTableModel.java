/*
 * @saoshao<1224165231@qq.com>
 */

package DetSql;

import javax.swing.table.AbstractTableModel;
import java.util.ArrayList;
import java.util.List;

//原始请求表格
public class PocTableModel extends AbstractTableModel {
    private final List<PocLogEntry> log;

    public PocTableModel() {
        this.log = new ArrayList<>();
    }

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
            case 0 -> "Name";
            case 1 -> "Poc";
            case 2 -> "BodyLength";
            case 3 -> "StatusCode";
            case 4 -> "Similarity";
            case 5 -> "Time(s)";
            case 6 -> "VulnState";
            default -> "";
        };
    }

    @Override
    public synchronized Object getValueAt(int rowIndex, int columnIndex) {
        PocLogEntry logEntry = log.get(rowIndex);
        return switch (columnIndex) {
            case 0 -> logEntry.getName();
            case 1 -> logEntry.getPoc();
            case 2 -> logEntry.getBodyLength();
            case 3 -> logEntry.getStatusCode();
            case 4 -> logEntry.getSimilarity();
            case 5 -> logEntry.getTime();
            case 6 -> logEntry.getVulnState();
            default -> "";
        };
    }

    public synchronized void add(List<PocLogEntry> logEntry) {
        // 空数据处理
        if (logEntry == null || logEntry.isEmpty()) {
            if (!log.isEmpty()) {
                int oldSize = log.size();
                log.clear();
                fireTableRowsDeleted(0, oldSize - 1);
            }
            return;
        }

        // 数据相同检查(通过hash比较,避免深度遍历)
        if (log.size() == logEntry.size()) {
            boolean same = true;
            for (int i = 0; i < log.size(); i++) {
                if (log.get(i).getMyHash() == null ||
                    !log.get(i).getMyHash().equals(logEntry.get(i).getMyHash())) {
                    same = false;
                    break;
                }
            }
            if (same) {
                return;  // 数据相同,无需更新
            }
        }

        // 数据变化,更新
        log.clear();
        log.addAll(logEntry);
        fireTableDataChanged();  // 使用更轻量的刷新方式
    }

    public synchronized PocLogEntry get(int rowIndex) {
        return log.get(rowIndex);
    }
}