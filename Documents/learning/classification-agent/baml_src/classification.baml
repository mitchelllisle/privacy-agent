class PayloadItemInput {
  name string
  description string?
  samples string[]?
}

class ItemClassification {
  name string
  classification "public" | "private" | "confidential" | "highly-confidential"
  rationale string
  confidence float
}

class ClassificationResult {
  classifications ItemClassification[]
}

function ClassifyPayloadItems(payload: PayloadItemInput[], policy_context: string) -> ClassificationResult {
  client "anthropic/claude-sonnet-4-20250514"
  prompt #"
    You are a data-classification agent.

    Classify each payload item into one of exactly these labels:
    - public
    - private
    - confidential
    - highly-confidential

    Policy:
    - public: information that is safe for public disclosure and does not include sensitive personal or commercial data.
    - private: internal-only values that are not sensitive PII and not commercially sensitive.
    - confidential: standard PII (for example name, date_of_birth, email, phone_number, ipv4_address) or sensitive internal business information.
    - highly-confidential: highly sensitive identity numbers (for example medicare_number, driver_license, passport_number, us_ssn, tax identifiers) and highly sensitive commercial information.

    Requirements:
    - Return one classification entry for every input payload item.
    - Preserve the exact input `name` in output `name`.
    - Use only the four allowed labels.
    - Include a short rationale grounded in item description and samples.
    - Set confidence between 0 and 1.
    - Keep output strictly typed. Do not wrap in markdown.

    Additional policy context:
    {{ policy_context }}

    Input payload:
    {{ payload }}
  "#
}


test sample_classification {
  functions [ClassifyPayloadItems]
  args {
    payload [
      {
        name "customer_email"
        description "Email address used for account notifications"
        samples ["alice@example.com", "bob@example.com"]
      }
      {
        name "marketing_banner_copy"
        description "Homepage hero message"
        samples ["Save 20% this week"]
      }
    ]
    policy_context "Apply strict classification policy."
  }
}
