package org.denialsafe;

import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Paths;
import org.wso2.balana.Balana;
import org.wso2.balana.PDP;
import org.wso2.balana.finder.impl.FileBasedPolicyFinderModule;

/** Minimal application adapter around the actual Balana PDP, not a policy evaluator. */
public final class BalanaBridge {
    private BalanaBridge() { }
    public static void main(String[] args) throws Exception {
        if (args.length != 2) throw new IllegalArgumentException("policy-directory request-file");
        java.io.PrintStream responseOut = System.out;
        System.setOut(System.err);
        System.setProperty(FileBasedPolicyFinderModule.POLICY_DIR_PROPERTY, args[0]);
        PDP pdp = new PDP(Balana.getInstance().getPdpConfig());
        String request = new String(Files.readAllBytes(Paths.get(args[1])), StandardCharsets.UTF_8);
        responseOut.println(pdp.evaluate(request));
    }
}
