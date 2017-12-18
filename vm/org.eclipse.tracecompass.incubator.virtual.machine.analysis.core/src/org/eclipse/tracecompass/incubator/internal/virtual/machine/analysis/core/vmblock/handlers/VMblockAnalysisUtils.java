package org.eclipse.tracecompass.incubator.internal.virtual.machine.analysis.core.vmblock.handlers;

import java.text.SimpleDateFormat;
import java.util.Date;

import org.eclipse.tracecompass.incubator.internal.virtual.machine.analysis.core.vmblock.blockAnalysisAttribute;
import org.eclipse.tracecompass.statesystem.core.ITmfStateSystemBuilder;
import org.eclipse.tracecompass.statesystem.core.exceptions.StateValueTypeException;
import org.eclipse.tracecompass.statesystem.core.exceptions.TimeRangeException;

/**
 * @author Hani Nemati
 *
 */
public class VMblockAnalysisUtils {



    private VMblockAnalysisUtils() {

    }


    /**
     * @param ssb
     * @param machinePTID
     * @param vCPUID
     * @return Status Quark for a specific VM's vCPU
     */
    public static int getvCPUStatus(ITmfStateSystemBuilder ssb, Integer machinePTID, Integer vCPUID) {
        return ssb.getQuarkAbsoluteAndAdd(blockAnalysisAttribute.VMS, machinePTID.toString(), blockAnalysisAttribute.VCPU, vCPUID.toString(), blockAnalysisAttribute.STATUS);
    }
    public static int getHypercallStatus(ITmfStateSystemBuilder ssb, Integer machinePTID, Integer vCPUID) {
        return ssb.getQuarkAbsoluteAndAdd(blockAnalysisAttribute.VMS, machinePTID.toString(), blockAnalysisAttribute.VCPU, vCPUID.toString(), "syscall");
    }
    public static int getHypercallName(ITmfStateSystemBuilder ssb, Integer machinePTID, Integer vCPUID) {
        return ssb.getQuarkAbsoluteAndAdd(blockAnalysisAttribute.VMS, machinePTID.toString(), blockAnalysisAttribute.VCPU, vCPUID.toString(), "syscallName");
    }
    /**
     * @param ssb
     * @param machinePTID
     * @param vCPUID
     * @return
     */
    public static int getLastExitQuark(ITmfStateSystemBuilder ssb, Integer machinePTID, Integer vCPUID) {
        return ssb.getQuarkAbsoluteAndAdd(blockAnalysisAttribute.VMS, machinePTID.toString(),  blockAnalysisAttribute.VCPU, vCPUID.toString(), blockAnalysisAttribute.LASTEXIT);
    }
    /**
     * @param vCPUStatusQuark
     * @param timestamp
     * @param value
     * @return
     * @throws TimeRangeException
     * @throws StateValueTypeException
     */
    public static void setvCPUStatus(ITmfStateSystemBuilder ssb, int vCPUStatusQuark, long timestamp, int value)
            throws TimeRangeException, StateValueTypeException {
        ssb.modifyAttribute(timestamp, value, vCPUStatusQuark);

    }
    public static void setSyscallName(ITmfStateSystemBuilder ssb, int syscallNameQuark, long timestamp, String value)
            throws TimeRangeException, StateValueTypeException {
        ssb.modifyAttribute(timestamp, value, syscallNameQuark);

    }
    public static void setCr3Value(ITmfStateSystemBuilder ssb, int cr3ValueQuark, long timestamp, String value)
            throws TimeRangeException, StateValueTypeException {
        ssb.modifyAttribute(timestamp, value, cr3ValueQuark);
    }
    /**
     * @param ssb
     * @param lastExitQuark
     * @param timestamp
     * @param value
     * @throws TimeRangeException
     * @throws StateValueTypeException
     */
    public static void setLastExit(ITmfStateSystemBuilder ssb, int lastExitQuark, long timestamp, int value)
            throws TimeRangeException, StateValueTypeException {
        ssb.modifyAttribute(timestamp, value, lastExitQuark);
    }
    /**
     * @param ssb
     * @param quark
     * @param timestamp
     * @param value
     * @throws TimeRangeException
     * @throws StateValueTypeException
     */
    public static void setProcessCr3Value(ITmfStateSystemBuilder ssb, int quark, long timestamp, int value)
            throws TimeRangeException, StateValueTypeException {
        ssb.modifyAttribute(timestamp, value, quark);
    }
    public static void setProcesstatus(ITmfStateSystemBuilder ssb, int quark, long timestamp, int value)
            throws TimeRangeException, StateValueTypeException {
        ssb.modifyAttribute(timestamp, value, quark);
    }

    private static String formatNs(long srcTime) {
        StringBuffer str = new StringBuffer();
        long ns = Math.abs(srcTime % 1000000000);
        String nanos = Long.toString(ns);
        str.append("000000000".substring(nanos.length())); //$NON-NLS-1$
        str.append(nanos);
        return str.substring(0, 9);
    }
    public static String formatTimeAbs(long time) {
        StringBuffer str = new StringBuffer();

        // format time from nanoseconds to calendar time HH:MM:SS
        SimpleDateFormat timeFormat = new SimpleDateFormat("HH:mm:ss"); //$NON-NLS-1$
        String stime = timeFormat.format(new Date(time / 1000000));
        str.append(stime);
        str.append('.');
        // append the Milliseconds, MicroSeconds and NanoSeconds as specified in
        // the Resolution
        str.append(formatNs(time));
        return str.toString();
    }


    public static int getCr3Status(ITmfStateSystemBuilder ss, Integer machinePTID, String cr3) {
        // TODO Auto-generated method stub
        return ss.getQuarkAbsoluteAndAdd(blockAnalysisAttribute.VMS, machinePTID.toString(),blockAnalysisAttribute.PROCESS, cr3, blockAnalysisAttribute.STATUS);

    }


    public static int getVcpuCr3Status(ITmfStateSystemBuilder ss, Integer machinePTID, Long vCPU_ID) {
        // TODO Auto-generated method stub
        return ss.getQuarkAbsoluteAndAdd(blockAnalysisAttribute.VMS, machinePTID.toString(), vCPU_ID.toString(), blockAnalysisAttribute.PROCESS, blockAnalysisAttribute.STATUS);
    }

    public static int getNestedVcpuStatus(ITmfStateSystemBuilder ss, Integer machinePTID, String cr3,Long vCPU_ID) {
        // TODO Auto-generated method stub
        return ss.getQuarkAbsoluteAndAdd(blockAnalysisAttribute.VMS, machinePTID.toString(), blockAnalysisAttribute.NESTED, cr3,  vCPU_ID.toString(), blockAnalysisAttribute.STATUS);
    }

    public static int getVcpuCr3Value(ITmfStateSystemBuilder ss, Integer machinePTID, Long vCPU_ID) {
        // TODO Auto-generated method stub
        return ss.getQuarkAbsoluteAndAdd(blockAnalysisAttribute.VMS, machinePTID.toString(), blockAnalysisAttribute.VCPU, vCPU_ID.toString(), blockAnalysisAttribute.PROCESS );
    }

    public static int getVcpuSpValue(ITmfStateSystemBuilder ss, Integer machinePTID, Long vCPU_ID) {
        // TODO Auto-generated method stub
        return ss.getQuarkAbsoluteAndAdd(blockAnalysisAttribute.VMS, machinePTID.toString(), blockAnalysisAttribute.VCPU, vCPU_ID.toString(), blockAnalysisAttribute.PROCESS,blockAnalysisAttribute.SP);
    }
    public static int getProcessCr3VcpuQuark(ITmfStateSystemBuilder ss, Integer machinePTID, String cr3) {
        // TODO Auto-generated method stub
        return ss.getQuarkAbsoluteAndAdd(blockAnalysisAttribute.VMS, machinePTID.toString(), blockAnalysisAttribute.PROCESS, cr3.toString(),blockAnalysisAttribute.VCPU);
    }
    public static int getProcessCr3StatusQuark(ITmfStateSystemBuilder ss, Integer machinePTID, String cr3) {
        // TODO Auto-generated method stub
        return ss.getQuarkAbsoluteAndAdd(blockAnalysisAttribute.VMS, machinePTID.toString(), blockAnalysisAttribute.PROCESS, cr3.toString(),blockAnalysisAttribute.STATUS );
    }
    public static int getProcessCr3WakeUpQuark(ITmfStateSystemBuilder ss, Integer machinePTID, String cr3) {
        // TODO Auto-generated method stub
        return ss.getQuarkAbsoluteAndAdd(blockAnalysisAttribute.VMS, machinePTID.toString(), blockAnalysisAttribute.PROCESS, cr3.toString(),blockAnalysisAttribute.WAKEUP );
    }
    public static int getThreadSPStatusQuark(ITmfStateSystemBuilder ss, Integer machinePTID, String sp) {
        // TODO Auto-generated method stub
        return ss.getQuarkAbsoluteAndAdd(blockAnalysisAttribute.VMS, machinePTID.toString(), blockAnalysisAttribute.THREADS,sp,blockAnalysisAttribute.STATUS );
    }
    public static int getThreadPPIDspQuark(ITmfStateSystemBuilder ss, Integer machinePTID, String sp) {
        // TODO Auto-generated method stub
        return ss.getQuarkAbsoluteAndAdd(blockAnalysisAttribute.VMS, machinePTID.toString(), blockAnalysisAttribute.THREADS,sp,blockAnalysisAttribute.PARRENT ); //$NON-NLS-1$
    }
    public static int getProcessCr3SPStatusQuark(ITmfStateSystemBuilder ss, Integer machinePTID, String cr3, String sp) {
        // TODO Auto-generated method stub
        return ss.getQuarkAbsoluteAndAdd(blockAnalysisAttribute.VMS, machinePTID.toString(), blockAnalysisAttribute.PROCESS, cr3.toString(),blockAnalysisAttribute.THREADS,sp.toString(),blockAnalysisAttribute.STATUS );
    }
    public static int getTimerQuark(ITmfStateSystemBuilder ss, Integer machinePTID) {
        // TODO Auto-generated method stub
        return ss.getQuarkAbsoluteAndAdd(blockAnalysisAttribute.VMS, machinePTID.toString(), "Wait" , "Timer"); //$NON-NLS-1$ //$NON-NLS-2$
    }
    public static int getTaskQuark(ITmfStateSystemBuilder ss, Integer machinePTID) {
        // TODO Auto-generated method stub
        return ss.getQuarkAbsoluteAndAdd(blockAnalysisAttribute.VMS, machinePTID.toString(), "Wait" , "Task"); //$NON-NLS-1$ //$NON-NLS-2$
    }
    public static int getDiskQuark(ITmfStateSystemBuilder ss, Integer machinePTID) {
        // TODO Auto-generated method stub
        return ss.getQuarkAbsoluteAndAdd(blockAnalysisAttribute.VMS, machinePTID.toString(), "Wait" , "Disk"); //$NON-NLS-1$ //$NON-NLS-2$
    }
    public static int getNetQuark(ITmfStateSystemBuilder ss, Integer machinePTID) {
        // TODO Auto-generated method stub
        return ss.getQuarkAbsoluteAndAdd(blockAnalysisAttribute.VMS, machinePTID.toString(), "Wait" , "Net"); //$NON-NLS-1$ //$NON-NLS-2$
    }

    public static int getUnknownQuark(ITmfStateSystemBuilder ss, Integer machinePTID) {
        // TODO Auto-generated method stub
        return ss.getQuarkAbsoluteAndAdd(blockAnalysisAttribute.VMS, machinePTID.toString(), "Wait" , "Unknown"); //$NON-NLS-1$ //$NON-NLS-2$
    }
    /**
     * @param ss
     * @param waitQuark
     * @param start
     * @param timerWait
     * @throws TimeRangeException
     * @throws StateValueTypeException
     */
    public static void setWait(ITmfStateSystemBuilder ss, int waitQuark, Long start, Long timerWait)
        // TODO Auto-generated method stub
        throws TimeRangeException, StateValueTypeException {
            ss.modifyAttribute(start, timerWait, waitQuark);
    }



}
