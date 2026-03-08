        if action == "TEST_SESSION":
            result = analyze_session_cookies(target)
            typer.echo("[✓] Session analysis executed")

        elif action == "ENUM_USER":
            result = check_username_enumeration(login_url, DEFAULT_TEST_USERS, delay_ms=delay_ms)
            typer.echo("[✓] Username enumeration executed")

        elif action == "TEST_RESET":
            reset_url = target.rstrip("/") + "/rest/user/reset-password"
            result = probe_reset_flow(reset_url, test_email or "test@example.com")
            typer.echo("[✓] Password reset flow tested")

        elif action == "TEST_MFA":
            import httpx
            try:
                r = httpx.get(target, timeout=8)
                mfa_signals = ["2fa", "two-factor", "otp", "verify"]
                detected = any(s in r.text.lower() for s in mfa_signals)
                result = {"mfa_detected": detected}
                typer.echo(f"[✓] MFA detection executed: {detected}")

                if not detected:
                    alert_logger.log_alert("MEDIUM", "MFA", "Multi-factor authentication not detected")

            except Exception as e:
                typer.echo(f"[!] MFA check failed: {e}")
                result = {"error": str(e)}

        elif action == "CONTROLLED_SPRAY":
            typer.echo("[!] Spray disabled for safety")
            result = {"skipped": True}

        all_findings[action] = result
        planner.record_finding(action, result)
