# Test Core Workflow

Run through the complete vault workflow to verify everything works:

```bash
rm -rf /tmp/test_vault
./target/release/vaultic --vault /tmp/test_vault init -n "Test" --password "test123!"
./target/release/vaultic --vault /tmp/test_vault unlock --password "test123!"
./target/release/vaultic --vault /tmp/test_vault add "GitHub" -u "user@test.com" -p "secret123"
./target/release/vaultic --vault /tmp/test_vault list
./target/release/vaultic --vault /tmp/test_vault status
./target/release/vaultic --vault /tmp/test_vault lock
```

Report success/failure of each step.
