package org.eclipse.tracecompass.incubator.internal.virtual.machine.analysis.core.vmblock.handlers;

import java.math.BigInteger;
import java.util.HashMap;
import java.util.Map;

import org.eclipse.jdt.annotation.Nullable;

/**
 * @author Hani Nemati
 *
 */
public class blockVMclass {

    private Integer lastFtid ;
    private int pid;
    private String name;
    private Long diskIrq;
    private Long netIrq;
    private Long vhostTid;
    private Integer wakedupTid;

    private Map<Integer, Long> read2time = new HashMap<>();
    private Map<Integer, Long> write2time = new HashMap<>();
    private Map<Integer, Long> read2block = new HashMap<>();
    private Map<Integer, Long> write2block = new HashMap<>();
    private Map<Integer, Long> read2latency = new HashMap<>();
    private Map<Integer, Long> write2latency = new HashMap<>();

    private static Map<String, blockNestedVMclass> nestedVM = new HashMap<>();
    private static Map<Integer, String> runningNestedVM = new HashMap<>();
    private static Map<Integer, String> runningNestedProcess = new HashMap<>();
    private Map<Integer,Long> vcpu2cacheMiss = new HashMap<>();
    private Map<Integer,Long> vcpu2cacheDiff = new HashMap<>();
    private static  Map<Integer,Integer> tid2vcpu = new HashMap<>();
    private static Map<Integer, String> vcpu2cr3Wakeup = new HashMap<>();
    private static Map<String,Integer> cr3toftid = new HashMap<>();
    private  Map<Integer,String> vcpu2cr3 = new HashMap<>();
    private  Map<Integer,String> vcpu2sp = new HashMap<>();
    private  Map<String,String> CR3toSP = new HashMap<>();
    private Map<Integer,String>  vcpu2InsideThread = new HashMap<>();
    private Map<Integer,BigInteger> vcpu2Thread = new HashMap<>();
    private  Map<Integer,Long> vcpu2tsStart = new HashMap<>() ;
    private  Map<Integer,Long> vcpu2tsEnd = new HashMap<>();

    private  Map<String,Long> cr3tsStart = new HashMap<>() ;
    private  Map<String,Long> cr3tsEnd = new HashMap<>();

    private  Map<String,Long>  wait = new HashMap<>();
    private  Map<Integer,Integer>  vcpuReasonSet = new HashMap<>();
    private Map<Integer,Integer> waitReason = new HashMap<>();
    public  Map<Integer,Integer> net2pid = new HashMap<>();
    public Long exitStart;
    public Map<Integer,Long>  exitTime = new HashMap<>();
    // vcpu 2 last exit reason
    public static Map<Integer,Integer> vcpu2er = new HashMap<>();
    public blockVMclass() {

    }
    public blockVMclass(int pid, int tid, int vcpu) {
        this.pid = pid;

        blockVMclass.tid2vcpu.put(tid, vcpu);
        this.exitStart = 0L;
        this.vhostTid = 0L;
        this.wakedupTid = 0;
    }
    public blockVMclass(int pid, int tid, int vcpu, String cr3) {
        this.pid = pid;
        blockVMclass.tid2vcpu.put(tid, vcpu);
        this.vcpu2cr3.put(vcpu, cr3);
        this.exitStart = 0L;
        lastFtid = 10;
        this.vhostTid = 0L;
        this.wakedupTid = 0;
    }
    public String runningNested(int vcpu) {
        if (runningNestedVM.containsKey(vcpu)) {
            return runningNestedVM.get(vcpu);
        }
        return "0"; //$NON-NLS-1$
    }
    public void setRunningNestedVM(int vcpu, String cr3) {
        runningNestedVM.put(vcpu, cr3);
    }
    public String getRunningNestedVM(int vcpu) {
        if (runningNestedVM.containsKey(vcpu)) {
            return runningNestedVM.get(vcpu);
        }
        return "0";
    }
    public void setRunningNestedProcess(int vcpu, String cr3) {
        runningNestedProcess.put(vcpu, cr3);
    }
    public String getRunningNestedProcess(int vcpu) {
        if (runningNestedProcess.containsKey(vcpu)) {
            return runningNestedProcess.get(vcpu);
        }
        return "0";
    }

    public boolean isNested(String mainKVMcr3) {
        if (nestedVM.containsKey(mainKVMcr3)) {
            return true;
        }
        return false;
    }
    public blockNestedVMclass getNestedVM(String mainKVMcr3) {
        if (nestedVM.containsKey(mainKVMcr3)) {
            return nestedVM.get(mainKVMcr3);
        }
        return null;
    }
    public void setNestedVM(String mainKVMcr3, blockNestedVMclass nested) {
        nestedVM.put(mainKVMcr3, nested);
    }


    public String getVcpu2cr3Wakeup(Integer vcpu) {
        if (vcpu2cr3Wakeup.containsKey(vcpu)) {
            return vcpu2cr3Wakeup.get(vcpu);
        }
        return "0";
    }

    public Long getRead2Time(Integer thread) {
        if (read2time.containsKey(thread)) {
            return read2time.get(thread);
        }
        return 0L;
    }

    public Long getWrite2Time(Integer thread) {
        if (write2time.containsKey(thread)) {
            return write2time.get(thread);
        }
        return 0L;
    }

    public void setRead2Time(Integer thread, Long time) {
        read2time.put(thread, time);
    }

    public void setWrite2Time(Integer thread, Long time) {
        write2time.put(thread, time);
    }

    public Long getRead2Block(Integer thread) {
        if (read2block.containsKey(thread)) {
            return read2block.get(thread);
        }
        return 0L;
    }
    public Long getWrite2Block(Integer thread) {
        if (write2block.containsKey(thread)) {
            return write2block.get(thread);
        }
        return 0L;
    }
    public Long addWrite2Block(Integer thread,Long ret) {
        Long sumBlock = 0L;
        if (write2block.containsKey(thread)) {
            sumBlock = write2block.get(thread);
        }
        sumBlock+= ret;
        write2block.put(thread, sumBlock);
        return sumBlock;
    }
    public Long addRead2Block(Integer thread,Long ret) {
        Long sumBlock = 0L;
        if (read2block.containsKey(thread)) {
            sumBlock = read2block.get(thread);
        }
        sumBlock+= ret;
        read2block.put(thread, sumBlock);
        return sumBlock;
    }

    public Long addReadLatency(Integer thread, Long latency) {
        Long sumLatency = 0L;
        if (read2latency.containsKey(thread)) {
            sumLatency = read2latency.get(thread);
        }
        sumLatency+= latency;
        read2latency.put(thread, sumLatency);
        return sumLatency;
    }
    public Long addWriteLatency(Integer thread, Long latency) {
        Long sumLatency = 0L;
        if (write2latency.containsKey(thread)) {
            sumLatency = write2latency.get(thread);
        }
        sumLatency+= latency;
        write2latency.put(thread, sumLatency);
        return sumLatency;
    }

    public Long getReadLatency(Integer thread) {

        if (read2latency.containsKey(thread)) {
            return read2latency.get(thread);
        }
        return 0L;
    }
    public Long getWriteLatency(Integer thread) {

        if (write2latency.containsKey(thread)) {
            return write2latency.get(thread);
        }
        return 0L;
    }


    public void setVcpu2cr3Wakeup(Integer vcpu, String cr3) {
        vcpu2cr3Wakeup.put(vcpu, cr3);
    }
    public void setNetworkWakeUp(Integer wakedupTid){
        this.wakedupTid = wakedupTid;
    }
    public Integer getNetworkWakeUp(){
        return wakedupTid ;
    }
    public Integer getLastFtid() {
        return lastFtid;
    }

    public void setLastFtid(Integer ftid) {
        lastFtid = ftid;
    }

    public Long getDiskIrq() {
        return diskIrq;
    }

    public long getCR3tsStart(String cr3) {
        if (cr3tsStart.containsKey(cr3)) {
            return cr3tsStart.get(cr3);
        }
        return 0L;
    }
    public void setcr3toftid(String cr3, Integer tid) {
        cr3toftid.put(cr3, tid);
    }
    public void removeCr3toFtid(String cr3) {
        cr3toftid.remove(cr3);
    }
    public Integer getcr3toftid(String cr3) {
        if (cr3toftid.containsKey(cr3)) {
            return cr3toftid.get(cr3);
        }
        return 0;

    }
    public void setCR3tsStart(String cr3, Long ts) {
        cr3tsStart.put(cr3, ts);
    }

    public long getCR3tsEnd(String cr3) {
        if (cr3tsEnd.containsKey(cr3)) {
            return cr3tsEnd.get(cr3);
        }
        return 0L;
    }

    public void setCR3tsEnd(String cr3, Long ts) {
        cr3tsEnd.put(cr3, ts);
    }

    public Long getWait(String reason) {
        if (wait.containsKey(reason)) {
            return this.wait.get(reason);
        }
        return 0L;
    }
    public Integer getVcpuReasonSet(Integer vcpu) {
        if (this.vcpuReasonSet.containsKey(vcpu)) {
            return this.vcpuReasonSet.get(vcpu);
        }
        this.vcpuReasonSet.put(vcpu, 0);
        return 0;
    }

    public Long getNetIrq() {
        return netIrq;
    }
    @Nullable
    public Long getTsStart(Integer vcpu) {
        if (vcpu2tsStart.containsKey(vcpu)) {
            return vcpu2tsStart.get(vcpu);
        }
        return null;
    }
    @Nullable
    public Long getTsEnd(Integer vcpu) {
        if (vcpu2tsEnd.containsKey(vcpu)) {
            return vcpu2tsEnd.get(vcpu);
        }
        return null;
    }

    public String getCR3toSP(String cr3) {
        if (CR3toSP.containsKey(cr3)) {
            return CR3toSP.get(cr3);
        }
        return null;
    }
    public void setCR3toSP(String cr3,String sp) {
        CR3toSP.put(cr3, sp);
    }
    @Nullable
    public Integer getvcpu(Integer tid) {
        if (tid2vcpu.containsKey(tid)) {
            return tid2vcpu.get(tid);
        }
        return null;
    }
    public String getVmName() {
        return name;
    }
    public int getVmPid() {
        return pid;
    }
    @Nullable
    public String getCr3(Integer vcpu) {
        if (this.vcpu2cr3.containsKey(vcpu)) {
            return this.vcpu2cr3.get(vcpu);
        }
        return null;
    }
    @Nullable
    public String getSp(Integer vcpu) {
        if (this.vcpu2sp.containsKey(vcpu)) {
            return this.vcpu2sp.get(vcpu);
        }
        return null;
    }
    @Nullable
    public Integer getLastExit(Integer vcpu) {
        if (vcpu2er.containsKey(vcpu)) {
            return vcpu2er.get(vcpu);
        }
        return 0;
    }
    public void setPid(int pid) {
        this.pid = pid;
    }
    public void setName(String name) {
        this.name = name ;
    }
    public void setTid2Vcpu(Integer tid, Integer vcpu) {
        tid2vcpu.put(tid, vcpu);
    }
    public void setVcpu2cr3(Integer vcpu, String cr3) {
        vcpu2cr3.put(vcpu, cr3);
    }
    public void setVcpu2sp(Integer vcpu, String sp) {
        vcpu2sp.put(vcpu, sp);
    }
    public void setLastExit(int vcpu,int reason) {
        vcpu2er.put(vcpu, reason);
    }
    public void setTsStart(int vcpu,Long ts) {
        vcpu2tsStart.put(vcpu, ts);
    }
    public void setTsEnd(int vcpu,Long ts) {
        vcpu2tsEnd.put(vcpu, ts);
    }
    public void setNetIrq(Long irq) {
        this.netIrq = irq;
    }
    public void setVhost(Long tid) {
        this.vhostTid = tid;
    }
    public Long getVhost() {
        return this.vhostTid;
    }
    public void setDiskIrq(Long irq) {
        this.diskIrq = irq;
    }
    public void setWait(String reason, long time) {
        this.wait.put(reason,time);
    }
    public void setVcpuReasonSet(Integer vcpu, Integer value) {
        this.vcpuReasonSet.put(vcpu, value);
    }
    public void setWaitReason(Integer vcpu, Integer value) {
        this.waitReason.put(vcpu, value);
    }
    public int getWaitReason(Integer vcpu) {
        if (waitReason.containsKey(vcpu)) {
            return waitReason.get(vcpu);
        }
        return 0;
    }
    public void setVcpu2InsideThread(int cpu, String insideThread) {
        vcpu2InsideThread.put(cpu, insideThread);
    }
    public String getVcpu2InsideThread(int cpu) {
        if (vcpu2InsideThread.containsKey(cpu)) {
            return vcpu2InsideThread.get(cpu);
        }
        return null;
    }

    public BigInteger getVcpu2Thread(int cpu) {
        if (vcpu2Thread.containsKey(cpu)) {
            return vcpu2Thread.get(cpu);
        }
        return BigInteger.ZERO;
    }
    public void setVcpu2Thread(int cpu, BigInteger thread) {

        vcpu2Thread.put(cpu,thread);


    }

    public void setVcpuCacheMiss(int vcpuID, Long cpuCacheMisses) {

        vcpu2cacheMiss.put(vcpuID, cpuCacheMisses);
    }
    public Long getVcpuCacheMiss(int vcpuID) {
        if (vcpu2cacheMiss.containsKey(vcpuID)) {
            return vcpu2cacheMiss.get(vcpuID);
        }
        return 0L;
    }

    public void setVcpuCacheDiff(int vcpuID, Long cpuCacheMisses) {

        vcpu2cacheDiff.put(vcpuID, cpuCacheMisses);
    }

    public Long getVcpuCacheDiff(int vcpuID) {
        if (vcpu2cacheDiff.containsKey(vcpuID)) {
            return vcpu2cacheDiff.get(vcpuID);
        }
        return 0L;
    }
}
