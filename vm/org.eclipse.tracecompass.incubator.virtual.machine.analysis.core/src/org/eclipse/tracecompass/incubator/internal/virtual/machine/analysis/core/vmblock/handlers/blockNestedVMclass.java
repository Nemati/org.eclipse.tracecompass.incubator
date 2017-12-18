package org.eclipse.tracecompass.incubator.internal.virtual.machine.analysis.core.vmblock.handlers;

import java.util.HashMap;
import java.util.Map;

public class blockNestedVMclass {
    private String mainKVMcr3;
    private static Map<Integer, String> lastCr3 = new HashMap<>();
    private static Map<Integer, String> preemptedProcess = new HashMap<>();
    private static Map<Integer, Long> blockTimeStamp = new HashMap<>();
    public blockNestedVMclass() {

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

    public blockNestedVMclass(String cr3) {
        mainKVMcr3 = cr3;
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
