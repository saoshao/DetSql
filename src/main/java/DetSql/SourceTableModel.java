/*
 * @saoshao<1224165231@qq.com>
 */

package DetSql;

import javax.swing.table.AbstractTableModel;
import java.util.ArrayList;
import java.util.List;

//原始请求表格
public class SourceTableModel extends AbstractTableModel {
    public final List<SourceLogEntry> log;

    public SourceTableModel() {
        this.log = new ArrayList<>();
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
        int index = log.size();
        log.add(logEntry);
        fireTableRowsInserted(index, index);
    }

    public synchronized void addx(SourceLogEntry logEntry, int index) {
        log.set(index, logEntry);

        fireTableRowsUpdated(index, index);
    }
    /**
     * 更新指定行的漏洞状态（VulnState列）
     * 用于在测试完成后更新表格中的漏洞检测结果
     *
     * @param entry      包含更新数据的日志条目
     * @param modelIndex 模型中的行索引
     * @param viewIndex  视图中的行索引（用于UI更新）
     */
    public synchronized void updateVulnState(SourceLogEntry entry, int modelIndex, int viewIndex) {
        log.set(modelIndex, entry);
        fireTableCellUpdated(viewIndex, 6); // 只更新VulnState列（第6列）
    }
    public synchronized SourceLogEntry get(int rowIndex) {
        return log.get(rowIndex);
    }

}