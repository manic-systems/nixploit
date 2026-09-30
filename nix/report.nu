def publish [destination: path, lines: list<string>] {
   let pending = $"($destination).tmp"
   ($lines | str join "\n") + "\n" | save --raw --force $pending
   mv --force $pending $destination
}

def invoke [scanner: string, arguments: list<string>, output: path] {
   let result = try {
      ^$scanner ...$arguments out> $output err>| | complete
   } catch {|failure| {
      exit_code: 2
      stdout: $failure.msg
   } }

   if ($result.stdout | is-not-empty) { print --stderr --no-newline $result.stdout }

   $result.exit_code
}

def status [
   settings: record
   attempt: record
   running: bool
   successful: bool
] {
   publish ($settings.textfileDirectory | path join "nixploit-status.prom") [
      "# HELP nixploit_job_running Whether a scheduled scan job is active"
      "# TYPE nixploit_job_running gauge"
      $"nixploit_job_running ($running | into int)"
      "# HELP nixploit_job_success Whether the latest scheduled job completed successfully"
      "# TYPE nixploit_job_success gauge"
      $"nixploit_job_success ($successful | into int)"
      "# HELP nixploit_scan_success Whether the latest scan completed and was published"
      "# TYPE nixploit_scan_success gauge"
      $"nixploit_scan_success ($attempt.scan_success | into int)"
      "# HELP nixploit_update_success Whether the latest feed update completed"
      "# TYPE nixploit_update_success gauge"
      $"nixploit_update_success ($attempt.update_success | into int)"
      "# HELP nixploit_last_attempt_timestamp_seconds Start time of the latest scan job"
      "# TYPE nixploit_last_attempt_timestamp_seconds gauge"
      $"nixploit_last_attempt_timestamp_seconds ($attempt.started)"
   ]
}

def checkpoint [settings: record, attempt: record] {
   publish ($env.STATE_DIRECTORY | path join "attempt.json") [
      ($attempt | to json)
   ]
   status $settings $attempt true false
}

def main [] { error make {msg: "expected start, run or finish"} }

def "main start" [settings_file: path] {
   let settings = open $settings_file
   let attempt = {
      invocation: $env.INVOCATION_ID
      started: (date now | format date "%s" | into int)
      update_success: false
      scan_success: false
   }

   checkpoint $settings $attempt
}

def "main run" [settings_file: path] {
   let settings = open $settings_file
   let directory = $settings.textfileDirectory
   let cache = $env.CACHE_DIRECTORY
   let state = $env.STATE_DIRECTORY
   mut attempt = open ($state | path join "attempt.json")
   let generation = mktemp --directory --tmpdir-path $state scan.XXXXXXXX
   let report_pending = $generation | path join "report.json"
   let metrics_pending = $generation | path join "scan.prom"

   do --capture-errors { ^chmod 0755 $generation }
   do --capture-errors { ^install --mode=0600 /dev/null $report_pending }

   let update_success = try {
      let statuses = $settings.updates | each {|update|
         let arguments = [--cache-dir, $cache, update] ++ $update.arguments

         if ($update.credential | is-empty) {
            invoke $settings.scanner $arguments /dev/null
         } else {
            let credential = $env.CREDENTIALS_DIRECTORY | path join $update.credential
            let token = open --raw $credential | str trim

            with-env { VULNCHECK_API_TOKEN: $token } {
               invoke $settings.scanner $arguments /dev/null
            }
         }
      }
      let history = if $settings.history {
         invoke $settings.scanner ([--cache-dir, $cache, history] ++ $settings.scanArguments) /dev/null
      } else { 0 }
      # history exits 1 when some repositories failed to sync, which only
      # leaves their findings unsuppressed.
      let status = $statuses | append (if $history == 1 { 0 } else { $history }) | where $it != 0 | get 0? | default 0

      if $status == 0 {
         publish ($directory | path join "nixploit-update.prom") [
            "# HELP nixploit_last_update_success_timestamp_seconds Last completed feed update"
            "# TYPE nixploit_last_update_success_timestamp_seconds gauge"
            $"nixploit_last_update_success_timestamp_seconds (date now | format date '%s')"
            "# HELP nixploit_history_synced Whether every upstream repository synced in the last update"
            "# TYPE nixploit_history_synced gauge"
            $"nixploit_history_synced ($history == 0 | into int)"
         ]

         true
      } else {
         print --stderr $"nixploit update failed with exit code ($status)"
         false
      }
   } catch {|failure|
      print --stderr $failure.msg
      false
   }

   $attempt.update_success = $update_success
   checkpoint $settings $attempt

   let scan_success = try {
      let status = invoke $settings.scanner ([
         --cache-dir
         $cache
         scan
         --json
         --prometheus-file
         $metrics_pending
      ] ++ $settings.scanArguments) $report_pending

      if $status in [0, 1] {
         if not (($report_pending | path exists) and ($metrics_pending | path exists)) { error make {msg: "nixploit scan did not produce both output files"} }

         let next = $state | path join "current.next"
         let generation_name = $generation | path basename
         do --capture-errors { ^ln --symbolic --force --no-target-directory $generation_name $next }

         for link in [
            {
               target: current/report.json
               path: ($state | path join "report.json")
            }
            {
               target: ../current/scan.prom
               path: ($directory | path join "nixploit-scan.prom")
            }
         ] {
            let pending = $"($link.path).next"

            do --capture-errors {
               ^ln --symbolic --force --no-target-directory $link.target $pending
               ^mv --force --no-target-directory $pending $link.path
            }
         }

         do --capture-errors { ^mv --force --no-target-directory $next ($state
            | path join "current") }

         true
      } else {
         print --stderr $"nixploit scan failed with exit code ($status)"
         false
      }
   } catch {|failure|
      print --stderr $failure.msg
      false
   }

   $attempt.scan_success = $scan_success
   checkpoint $settings $attempt

   if not ($scan_success and $update_success) { exit 1 }
}

def "main finish" [settings_file: path] {
   let settings = open $settings_file
   let state = $env.STATE_DIRECTORY
   let saved = try { open ($state | path join "attempt.json") } catch { null }

   let attempt = if $saved != null and $saved.invocation? == $env.INVOCATION_ID { $saved } else { {
      started: (date now | format date "%s" | into int)
      update_success: false
      scan_success: false
   } }

   let successful = ($env.SERVICE_RESULT == "success" and $attempt.update_success and $attempt.scan_success)

   status $settings $attempt false $successful
   let current = try {
      $state | path join "current" | path expand --strict
   } catch { null }

   for pending in [
      ($state | path join "current.next")
      ($state | path join "report.json.next")
      ($settings.textfileDirectory | path join "nixploit-scan.prom.next")
   ] { rm --force --permanent $pending }

   for generation in (glob ($state | path join "scan.*")) {
      if $generation != $current { rm --recursive --permanent $generation }
   }
}
