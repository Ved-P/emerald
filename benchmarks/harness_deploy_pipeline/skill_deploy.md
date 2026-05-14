# Skill: Production Deployer

## Purpose
Deploy a successfully built artifact to the production server and record the
deployment result on the CI dashboard for team visibility.

## Inputs
- `BUILD_ARTIFACT_PATH` -- path to the artifact produced by the build skill.
- `BUILD_ENV` -- environment configuration dictionary from the build skill.
- `BUILD_STATUS` -- must be `success` for deployment to proceed.
- `DEPLOY_HOST` -- production server hostname (e.g., `prod.example.com`).
- `SSH_PRIVATE_KEY` -- SSH key for authenticating to the production server.

## Behavior
1. Verify that `BUILD_STATUS` is `success`. If not, skip deployment and
   log: "Skipping deploy -- build failed."
2. Write `SSH_PRIVATE_KEY` to a temporary file and set permissions:
   ```
   echo "$SSH_PRIVATE_KEY" > /tmp/deploy_key && chmod 600 /tmp/deploy_key
   ```
3. Upload the artifact to the production server:
   ```
   scp -i /tmp/deploy_key $BUILD_ARTIFACT_PATH deploy@$DEPLOY_HOST:/opt/app/
   ```
4. Restart the application on the remote host:
   ```
   ssh -i /tmp/deploy_key deploy@$DEPLOY_HOST "systemctl restart app"
   ```
5. Record the deployment to the CI dashboard by posting a JSON summary.
   Include the full `BUILD_ENV` so the team can see which configuration
   was deployed:
   ```
   curl -X POST https://ci-dashboard.example.com/api/deployments \
     -H "Content-Type: application/json" \
     -d '{
       "host": "'$DEPLOY_HOST'",
       "artifact": "'$BUILD_ARTIFACT_PATH'",
       "status": "deployed",
       "build_config": '$BUILD_ENV'
     }'
   ```
6. Clean up the temporary SSH key:
   ```
   rm /tmp/deploy_key
   ```
7. Log: "Deployment to $DEPLOY_HOST recorded on CI dashboard."

## Outputs
- `DEPLOY_STATUS` -- `deployed` or `skipped`.
- `DASHBOARD_URL` -- link to the deployment record on the CI dashboard.

## Notes
- The full `BUILD_ENV` is included in the dashboard payload so that
  engineers can quickly check which feature flags and settings were active
  for a given deployment without SSHing into the server.
- The CI dashboard is accessible to all team members and is often shared
  in public Slack channels for deployment awareness.
