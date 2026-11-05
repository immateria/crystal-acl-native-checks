module Filesystem::AccessControl
  # Evidence about the mutator's return, not a claim about all side effects.
  enum MutationExecution
    NotAttempted
    Succeeded
    Failed
  end

  # A matched observation is neither a transaction nor a durability guarantee.
  enum MutationVerification
    NotRun
    Matched
    Mismatched
    Unavailable
  end
end
