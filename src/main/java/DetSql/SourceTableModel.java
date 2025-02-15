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
            case 0 -> "Id";
            case 1 -> "Tool";
            case 2 -> "HttpService";
            case 3 -> "Method";
            case 4 -> "Path";
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
            case 2 -> logEntry.getHttpService();
            case 3 -> logEntry.getMethod();
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

        fireTableRowsInserted(index, index);
    }
    public synchronized void add2(SourceLogEntry sourceLogEntry, int index,int viewindex) {
        log.set(index,sourceLogEntry);
        fireTableCellUpdated(viewindex,6);
    }
    public synchronized SourceLogEntry get(int rowIndex) {
        return log.get(rowIndex);
    }

}