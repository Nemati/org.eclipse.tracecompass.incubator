package org.eclipse.tracecompass.incubator.internal.virtual.machine.analysis.core.vmblock;

public interface blockAnalysisAttribute {


    /**
     *
     */
    String CPUS = "CPUs"; //$NON-NLS-1$
    /**
     *
     */
    String THREADS = "Threads"; //$NON-NLS-1$
    /**
     *
     */
    String HOSTS = "Hosts"; //$NON-NLS-1$
    /**
     *
     */
    String QEMUNAME = "qemu-system-x86"; //$NON-NLS-1$
    /**
     *
     */
    String PROCESS = "Process"; //$NON-NLS-1$
    /**
     *
     */
    String VMS = "VMs"; //$NON-NLS-1$
    /**
     *
     */
    String STATUS = "Status"; //$NON-NLS-1$
    String SP = "Sp"; //$NON-NLS-1$
    String VCPU = "vCPU"; //$NON-NLS-1$
    String LASTEXIT = "LastExit"; //$NON-NLS-1$
    String PARRENT = "Parrent"; //$NON-NLS-1$
    String WAKEUP = "WakeUp";//$NON-NLS-1$
    String NESTED = "Nested" ; //$NON-NLS-1$
    String CacheMiss = "CacheMiss";
}
