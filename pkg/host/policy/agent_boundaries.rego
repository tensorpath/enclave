package tensorpath.agent.policy

import future.keywords.in

default allow_network = false
default allowed_read_paths = []
default allowed_write_paths = ["/tmp/"] # Agents can always write to tmp

# Allow network ONLY if the intent requires it AND the role permits it
allow_network {
    input.intent.network_required == true
    input.user_role == "researcher"
}

# Determine allowed read paths
allowed_read_paths = paths {
    # If the action is read-only analysis, grant access to requested paths
    input.intent.action_category == "read_only_analysis"
    paths := input.intent.requested_paths
}

# Construct the final verdict payload
verdict = {
    "allow_network": allow_network,
    "allowed_read_paths": allowed_read_paths,
    "allowed_write_paths": allowed_write_paths
}
