class ReviewedMatch {
  path string
  types string[]
  is_valid bool
  confidence float?
  reason string?
}

function ReviewPIIDetection(detections: string, context: string) -> ReviewedMatch[] {
  client "anthropic/claude-sonnet-4-20250514"
  prompt #"
    You are a privacy detection reviewer. Your task is to validate whether each detected PII entry is correct.

    You will be given a list of detections from a PII detection agent and the original field context that was analyzed.

    For each detection:
    - Confirm whether the detected PII type(s) are correct for the given path and value.
    - Set is_valid to true only if the detection is a genuine true positive.
    - Set is_valid to false if the detection is a false positive or the types are incorrect.
    - Assign a confidence score between 0 and 1 for your review decision.
    - Provide a brief, evidence-based reason for your decision.

    Guidelines:
    - Be critical and reduce false positives.
    - Consider both the field name and the value when making your decision.
    - If a detection correctly identifies PII, mark it valid even if you would assign a different confidence than the original detector.
    - If a detection misclassifies the PII type but the field is genuinely PII, mark it invalid and note the correct type.

    Detections to review (path | types | confidence | reason):
    {{ detections }}

    Original field context (path: value):
    {{ context }}
  "#
}

test sample_review {
  functions [ReviewPIIDetection]
  args {
    detections #"
      $.email | email | 0.97 | Matches canonical email pattern.
      $.notes | credit_card | 0.85 | Contains card-like digits.
    "#
    context #"
      $.email: alice@example.com
      $.notes: card 4242 4242 4242 4242
    "#
  }
}
