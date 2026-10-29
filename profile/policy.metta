!(import! &self (library Omega ./profile/policy.py))

(= (securityPolicyPath) (empty))

(= (applySecurityPolicy)
   (progn (log INFO "policy" "Configuring security policy")
          (configure securityPolicyPath "./repos/Omega/profile/policy-native.yaml")
          (py-call (policy.apply_security_policy (securityPolicyPath)))
          True))
