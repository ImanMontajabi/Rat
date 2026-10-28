The helper no longer stops enforcing rules after running for a while: every pfctl run left a file open until it hit the system's limit, after which pf could not be checked, repaired or updated.
