package org.eclipse.tracecompass.incubator.internal.virtual.machine.analysis.core.vmblock.handlers;

import java.util.HashMap;
import java.util.Map;

import org.eclipse.jdt.annotation.Nullable;

/**
 * @author Hani Nemati
 *
 */
public class blockVMclass {
    private int pid;
    private String name;
    private Long diskIrq;
    private Long netIrq;
    private static  Map<Integer,Integer> tid2vcpu = new HashMap<>();
    private  Map<Integer,String> vcpu2cr3 = new HashMap<>();
    private  Map<Integer,String> vcpu2sp = new HashMap<>();
    private  Map<Integer,Long> vcpu2tsStart = new HashMap<>() ;
    private  Map<Integer,Long> vcpu2tsEnd = new HashMap<>();
    private  Map<String,Long>  wait = new HashMap<>();
    private  Map<Integer,Integer>  vcpuReasonSet = new HashMap<>();
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
    }
    public blockVMclass(int pid, int tid, int vcpu, String cr3) {
        this.pid = pid;
        blockVMclass.tid2vcpu.put(tid, vcpu);
        this.vcpu2cr3.put(vcpu, cr3);
        this.exitStart = 0L;
    }
    public Long getDiskIrq() {
        return diskIrq;
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
        return null;
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
    public void setDiskIrq(Long irq) {
        this.diskIrq = irq;
    }
    public void setWait(String reason, long time) {
        this.wait.put(reason,time);
    }
    public void setVcpuReasonSet(Integer vcpu, Integer value) {
        this.vcpuReasonSet.put(vcpu, value);

    }
}
