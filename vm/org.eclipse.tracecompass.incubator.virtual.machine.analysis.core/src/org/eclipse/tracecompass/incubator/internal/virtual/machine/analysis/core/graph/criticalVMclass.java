package org.eclipse.tracecompass.incubator.internal.virtual.machine.analysis.core.graph;

import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Vector;

import org.eclipse.jdt.annotation.Nullable;



/**
 * @author Hani Nemati
 *
 */
public class criticalVMclass {

    class wakeeClass {
        String wakerCr3;
        Long wakerPid;
        Integer ftid;
        public wakeeClass(String cr3, Long pid, Integer ftid) {
            this.wakerCr3 = cr3;
            this.wakerPid = pid;
            this.ftid = ftid;
        }
        public String getCr3() {
            return this.wakerCr3;
        }
        public Long getPid() {
            return this.wakerPid;
        }
        public Integer getWakeeftid() {
            return this.ftid;
        }
    }

    private Integer pid;
    private Integer networkIRQ;
    private Integer diskIRQ;
    private static Map<String, Integer> acceptIrq = new HashMap<>();
    private static  Map<Integer,Integer> tid2vcpu = new HashMap<>();
    private static  Map<Integer,wakeeClass> wakee = new HashMap<>();
    private static Map<String,Integer> cr3toftid = new HashMap<>();
    private static Map<Integer,String> vcpu2cr3 = new HashMap<>();
    private static Map<Integer,Integer> vcpu2exit = new HashMap<>();
    public List nestedVMcr3 = new Vector();

    private static Map<String, criticalVMclass> nestedVM = new HashMap<>();

    private static Map<Integer,Integer> vcpu2Wait = new HashMap<>();
    private static Map<Integer,String> processOnNestedVM = new HashMap<>();

    private static Map<Integer,String> vcpuToNestedVM = new HashMap<>();
    public criticalVMclass(int pid) {
        this.pid = pid;
        this.networkIRQ = 0;
        this.diskIRQ = 0;

    }

    public void setWaitReason(Integer vcpu,Integer reason) {
        vcpu2Wait.put(vcpu, reason);
    }
    public Integer getWaitReason(Integer vcpu) {
        if (vcpu2Wait.containsKey(vcpu)) {
            vcpu2Wait.get(vcpu);
        }
        return 0;

    }

    public void putNestedVM(String cr3, criticalVMclass nested) {
        nestedVM.put(cr3, nested);

    }

    public @Nullable criticalVMclass getNestedVM(String cr3) {
        if (nestedVM.containsKey(cr3)) {
            return nestedVM.get(cr3);
        }
        return null;
    }

    public void setVcpu2exit(Integer vcpu, Integer exit) {
        vcpu2exit.put(vcpu, exit);
    }
    public Integer getExit(Integer vcpu) {
        if(vcpu2exit.containsKey(vcpu)) {
            Integer exitReason = vcpu2exit.get(vcpu);
            return exitReason;
        }
        return 0;
    }

    public void setProcessOnNestedVM(Integer vcpu, String cr3) {
        processOnNestedVM.put(vcpu, cr3);
    }
    public String getProcessOnNestedVM(Integer vcpu) {
        if (processOnNestedVM.containsKey(vcpu)) {
            String cr3 = processOnNestedVM.get(vcpu);
            return cr3;
        }
        return "2412";
    }

    public boolean isNestedVM(String cr3) {
        if (nestedVMcr3.contains(cr3)) {
            return true;
        }
        return false;
    }
    public void setNestedVMonCPU(Integer vcpu, String cr3) {
        if (!nestedVMcr3.contains(cr3)) {
            nestedVMcr3.add(cr3);
        }
        vcpuToNestedVM.put(vcpu, cr3);
    }

    public String getNestedVMonCPU( Integer vcpu) {

        if (vcpuToNestedVM.containsKey(vcpu)) {
            String cr3 = vcpuToNestedVM.get(vcpu);
            return cr3;
        }
        return "2412";
    }
    public void setAcceptIrq(String cr3, int yes) {
        acceptIrq.put(cr3, yes);
    }
    public Integer getAcceptIrq(String cr3) {
        if (acceptIrq.containsKey(cr3)) {
            Integer integer = acceptIrq.get(cr3);
            return integer;
        }
        return 0;
    }
    public void setWakee(int vcpu,Long pid, String cr3, Integer ftid) {
        wakeeClass wakee1 = new wakeeClass(cr3, pid,ftid);
        wakee.put(vcpu,wakee1);
    }
    public wakeeClass getWakee(int vcpu) {
        if (wakee.containsKey(vcpu)) {
            wakeeClass wakee1 = wakee.get(vcpu);
            return wakee1;
        }
        wakeeClass wakee2 = new wakeeClass("0",0L,0);
        return wakee2;
    }
    public Integer getPid() {
        return this.pid;
    }
    public Integer getNetworkIRQ() {
        return this.networkIRQ;
    }
    public Integer getDiskIRQ() {
        return this.diskIRQ;
    }

    public Integer getVcpu(Integer tid) {
        if (tid2vcpu.containsKey(tid)) {
            Integer integer = tid2vcpu.get(tid);
            return integer;
        }
        return -1;
    }
    public Integer getFtid(String cr3) {
        if (cr3toftid.containsKey(cr3)) {
            Integer integer = cr3toftid.get(cr3);
            return integer;
        }

        return -1;
    }
    public String getCr3(Integer vcpu) {
        if (vcpu2cr3.containsKey(vcpu)) {
            String string = vcpu2cr3.get(vcpu);
            return string;
        }

        return "0";
    }
    public void setCr3(Integer vcpu, String cr3) {
        vcpu2cr3.put(vcpu, cr3);
    }
    public void setFtid(String cr3, Integer ftid) {
        cr3toftid.put(cr3, ftid);
    }
    public void setVcpu(Integer tid, Integer vcpu) {
        tid2vcpu.put(tid, vcpu);
    }
    public void setNetworkIRQ(Integer irqNumber) {
        this.networkIRQ = irqNumber;
    }
    public void setDiskIRQ(Integer irqNumber) {
        this.diskIRQ = irqNumber;
    }



}
