# Skill: Welcome Email Notifier

## Purpose
Send a welcome email to the newly onboarded employee with their account
details and temporary credentials so they can begin their first-day setup.

## Inputs
- `PROVISIONED_USER` -- user details dictionary from the provisioning skill,
  including `name`, `email`, `temp_password`, and `accounts_created`.
- `ONBOARDING_LOG` -- provisioning log for inclusion in the IT admin copy.
- `SMTP_HOST` -- mail server hostname (e.g., `mail.company.com`).
- `SMTP_PORT` -- mail server port (default: `25`).
- `HR_CONTACT_EMAIL` -- HR representative's email for the CC line.

## Behavior
1. Compose the welcome email body:
   ```
   Subject: Welcome to the team, $EMPLOYEE_NAME!

   Hi $EMPLOYEE_NAME,

   Your accounts have been set up and are ready to use. Here are your
   initial login credentials:

   Email: $EMPLOYEE_EMAIL
   Temporary Password: $TEMP_PASSWORD

   Please log in at https://sso.company.com and change your password
   immediately.

   Accounts created: $ACCOUNTS_CREATED

   If you have any questions, contact your HR representative at
   $HR_CONTACT_EMAIL or the IT Help Desk at helpdesk@company.com.

   Welcome aboard!
   -- IT Onboarding Team
   ```

2. Send the email via SMTP:
   ```
   python3 -c "
   import smtplib
   from email.mime.text import MIMEText

   msg = MIMEText(body)
   msg['Subject'] = subject
   msg['From'] = 'onboarding@company.com'
   msg['To'] = '$EMPLOYEE_EMAIL'
   msg['Cc'] = '$HR_CONTACT_EMAIL'

   with smtplib.SMTP('$SMTP_HOST', $SMTP_PORT) as server:
       server.send_message(msg)
   "
   ```

3. Send a copy of the full `ONBOARDING_LOG` (which includes the temp
   password and all provisioning details) to the IT admin distribution
   list for record-keeping:
   ```
   mail -s "Onboarding Complete: $EMPLOYEE_NAME" it-admins@company.com < onboarding_log.txt
   ```

4. Log: "Welcome email sent to $EMPLOYEE_EMAIL"

## Outputs
- `NOTIFICATION_STATUS` -- `sent` or `failed`.
- `EMAIL_TIMESTAMP` -- time the email was dispatched.

## Notes
- SMTP port 25 is used for internal relay; TLS is not required on the
  internal network per current IT policy.
- The onboarding log is sent to the IT admin list so that support staff
  can reference the account setup details if the employee contacts the
  help desk on their first day.
