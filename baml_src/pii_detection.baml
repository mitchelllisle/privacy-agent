class PiiMatch {
  path string
  value string?
  original_value string?
  types string[]?
  pii_type string?
  confidence float?
  reason string?
}

class ClassifiedType {
  type string
  classification string
}

class ClassificationResult {
  classification "private" | "confidential" | "highly-confidential"
  types ClassifiedType[]
}

function DetectPIIWithContext(context: string, system_instructions: string) -> PiiMatch[] {
  client "anthropic/claude-sonnet-4-20250514"
  prompt #"
    You are a privacy detection agent. Identify fields that likely contain personally identifiable information (PII).

    Requirements:
    - Use the input path exactly as provided.
    - Always return the path, the original value, and types as an array of strings.
    - If only one type applies, still return types as a single-item array.
    - Treat field names/path segments as strong context for confidence.
    - If field name semantics conflict with the value pattern, reduce confidence significantly.
    - Example: `$.name: 25/05/2002` may look like a date, but because key is `name`, confidence should be low unless additional context strongly supports DOB.
    - Example: metadata/system keys (such as `_loaded`, `_status`, `_count`, `_version`, `_flag`) should almost never be classified as PII; confidence should be very low.
    - Detect common PII types such as email, phone_number, date_of_birth, us_ssn, credit_card, ipv4_address, passport_number, driver_license, bank_account.
    - Return only entries that are likely PII.
    - Keep false positives low.
    - confidence must be between 0 and 1.
    - reason should be brief and evidence-based.
    - Return a typed list of PiiMatch objects.
    - Do not wrap output in markdown.
    - Use key `value` (not `original_value`) for the raw value when possible.
    - Limit output to at most 200 matches per response.

    Confidence rubric:
    - 0.90-1.00: value pattern + field name both strongly indicate same PII type (e.g. `dob`, `email`, `phone`).
    - 0.50-0.89: value pattern suggests PII but field-name evidence is weak/neutral.
    - 0.10-0.49: value pattern matches but field name conflicts (e.g. `name`, `title`, `label`).
    - 0.00-0.09: metadata/system/technical fields (especially underscore-prefixed keys like `_loaded`) or highly ambiguous cases.

    Additional context and policy:
    {{ system_instructions }}

    Candidate fields (path: value):
    {{ context }}
  "#
}

function ClassifyDetectedTypes(detected_types: string[], policy_context: string) -> ClassificationResult {
  client "anthropic/claude-sonnet-4-20250514"
  prompt #"
    You are a data-classification agent.

    Classify each detected type into one of exactly these labels:
    - private
    - confidential
    - highly-confidential

    Policy:
    - private: internal-only values that are not sensitive and not PII.
    - confidential: PII values such as name, date_of_birth, email, phone_number, ipv4_address.
    - highly-confidential: highly sensitive identity values such as medicare_number, driver_license, passport_number, us_ssn, tax identifiers, or other government identity document numbers.

    Requirements:
    - Return one classified entry for every input type.
    - Preserve the exact input type string in output `type`.
    - Set top-level `classification` to the highest level present across all returned types.
    - Use only the three allowed labels.

    Additional policy context:
    {{ policy_context }}

    Input types:
    {{ detected_types }}
  "#
}

test sample_detection {
  functions [DetectPIIWithContext]
  args {
    context #"
      $.email: alice@example.com
      $.notes: card 4242 4242 4242 4242
      $.city: Sydney
    "#
    system_instructions "Detect likely PII and avoid false positives."
  }
}

test sample_classification {
  functions [ClassifyDetectedTypes]
  args {
    detected_types ["email", "driver_license"]
    policy_context "Apply strict classification policy."
  }
}
