package org.eclipse.tracecompass.incubator.internal.virtual.machine.analysis.core.vmblock.handlers;

import java.util.HashMap;
import java.util.Map;

public class blockNestedVMclass {
    private String mainKVMcr3;
    private static Map<Integer, String> lastCr3 = new HashMap<>();
    private static Map<Integer, String> preemptedProcess = new HashMap<>();
    private static Map<Integer, Long> blockTimeStamp = new HashMap<>();
    private static Map<String,Integer> cr3toftid = new HashMap<>();
    private static Map<Integer, String> runningNestedProcess = new HashMap<>();
    private static Map<String,Long> cr3BlockTS = new HashMap<>();
    private Integer lastFtid ;

    public Long getBlockTimeStampProcess(String cr3) {
        if (cr3BlockTS.containsKey(cr3)) {
            return cr3BlockTS.get(cr3);
        }
        return 0L;
    }
    public void setBlockTimeStampProcess(String cr3, Long ts) {
        cr3BlockTS.put(cr3, ts);
    }
    public String getRunningNestedProcess(Integer vcpu) {
        if (runningNestedProcess.containsKey(vcpu)) {
            return runningNestedProcess.get(vcpu);
        }
        return "0";
    }
    public void setRunningNestedProcess(Integer vcpu, String cr3) {
        runningNestedProcess.put(vcpu, cr3);
    }

    public Integer getLastFtid() {
        return lastFtid;
    }

    public void setLastFtid(Integer ftid) {
        lastFtid = ftid;
    }

    public blockNestedVMclass() {
        lastFtid = 10;
    }
    public blockNestedVMclass(String cr3) {
        mainKVMcr3 = cr3;
        lastFtid = 10;
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
    public void setBlockTimeStamp(Integer vcpu, Long ts) {
        blockTimeStamp.put(vcpu, ts);
    }
    public Long getBlockTimeStamp(Integer vcpu) {
        if (blockTimeStamp.containsKey(vcpu)) {
            return blockTimeStamp.get(vcpu);
        }
        return 0L;
    }
    public void setLastCr3(Integer vcpu, String cr3) {
        lastCr3.put(vcpu, cr3);
    }

    public String getLastCr3(Integer vcpu) {
        if (lastCr3.containsKey(vcpu)) {
            return lastCr3.get(vcpu);
        }
        return "0";
    }



    public void setMainKVMcr3(String cr3) {
        mainKVMcr3 = cr3;
    }
    public String getMainKVMcr3() {
        return mainKVMcr3;
    }
    public void setPreemptedProcess(Integer vcpu, String lastNestedVMcr3) {
        preemptedProcess.put(vcpu,lastNestedVMcr3);
    }
    public String getPreemptedProcess(Integer vcpu) {
        if (preemptedProcess.containsKey(vcpu)) {
            return preemptedProcess.get(vcpu);
        }
        return "0";
    }
}
