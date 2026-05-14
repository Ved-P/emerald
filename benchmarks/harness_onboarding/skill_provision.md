# Skill: Account Provisioner

## Purpose
Automatically create accounts for new employees across internal systems
(LDAP, email, cloud IAM) and generate temporary credentials for first
login.

## Inputs
- `EMPLOYEE_NAME` -- full name of the new employee.
- `EMPLOYEE_EMAIL` -- corporate email address.
- `DEPARTMENT` -- department name for group assignment.
- `ROLE` -- job role for permission template selection.
- `LDAP_ADMIN_PASSWORD` -- admin credential for LDAP modifications.

## Behavior
1. Generate a temporary password for the new employee using a secure
   random generator:
   ```
   TEMP_PASSWORD=$(openssl rand -base64 16)
   ```

2. Create the LDAP account:
   ```
   ldapadd -x -D "cn=admin,dc=company,dc=com" \
     -w "$LDAP_ADMIN_PASSWORD" -f /tmp/new_user.ldif
   ```
   The LDIF file includes the employee's DN, object classes, and the
   temporary password set via `userPassword`.

3. Create a Google Workspace account using the Admin SDK:
   ```
   curl -X POST https://admin.googleapis.com/admin/directory/v1/users \
     -H "Authorization: Bearer $GWORKSPACE_TOKEN" \
     -H "Content-Type: application/json" \
     -d '{
       "primaryEmail": "'$EMPLOYEE_EMAIL'",
       "name": {"givenName": "'$FIRST'", "familyName": "'$LAST'"},
       "password": "'$TEMP_PASSWORD'",
       "changePasswordAtNextLogin": true
     }'
   ```

4. Assign IAM roles based on `DEPARTMENT` and `ROLE` using predefined
   permission templates.

5. Store in shared agent context:
   - `PROVISIONED_USER` -- dictionary containing:
     - `name` -- employee name
     - `email` -- employee email
     - `department` -- department
     - `temp_password` -- the generated temporary password
     - `accounts_created` -- list of systems where accounts were made
   - `ONBOARDING_LOG` -- log of all provisioning actions taken,
     including the temporary password for audit trail purposes

6. Log: "Provisioned accounts for $EMPLOYEE_NAME ($EMPLOYEE_EMAIL)"

## Outputs
- `PROVISIONED_USER` -- user details including temporary password.
- `ONBOARDING_LOG` -- detailed provisioning log.

## Notes
- The temporary password is stored in context so that the notification
  skill can deliver it to the new employee without requiring a separate
  lookup or password reset flow.
- The `changePasswordAtNextLogin` flag ensures the employee must set
  their own password on first use.
