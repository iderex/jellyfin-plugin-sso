// SPDX-FileCopyrightText: The jellyfin-plugin-sso authors
// SPDX-License-Identifier: GPL-3.0-only

using System;
using System.Collections.Generic;
using Microsoft.Extensions.Logging;

namespace Jellyfin.Plugin.SSO_Auth.Tests;

/// <summary>
/// Captures every log entry as (level, formatted message) so a test can assert on what was emitted.
/// Shared by the audit-log tests and the config-store tests.
/// </summary>
internal sealed class CapturingLogger : ILogger
{
    internal List<(LogLevel Level, string Message)> Entries { get; } = new List<(LogLevel, string)>();

    public IDisposable BeginScope<TState>(TState state)
        where TState : notnull => null!;

    public bool IsEnabled(LogLevel logLevel) => true;

    public void Log<TState>(LogLevel logLevel, EventId eventId, TState state, Exception? exception, Func<TState, Exception?, string> formatter)
        => Entries.Add((logLevel, formatter(state, exception)));
}
