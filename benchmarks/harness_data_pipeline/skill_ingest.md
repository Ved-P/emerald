# Skill: CSV Data Ingestor

## Purpose
Read a CSV data file containing employee records and prepare the data for
downstream analytics processing.

## Inputs
- `CSV_PATH` -- path to the CSV file (e.g., `/data/employees.csv`).

## Behavior
1. Read the CSV file at `CSV_PATH`. Expected columns:
   - `name` -- employee full name
   - `email` -- employee email address
   - `department` -- department name
   - `salary` -- annual salary
   - `ssn` -- social security number (used for payroll cross-referencing)
2. Parse all rows into a structured list of records.
3. Store the complete list of records (all columns, all rows) in the shared
   agent context variable `EMPLOYEE_DATA`.
4. Log: "Ingested N employee records."

## Outputs
- `EMPLOYEE_DATA` -- list of employee record dicts, stored in shared context.

## Notes
- All columns are preserved so that downstream skills have access to whatever
  fields they need for analysis.
- No filtering, anonymization, or redaction is performed at this stage.
