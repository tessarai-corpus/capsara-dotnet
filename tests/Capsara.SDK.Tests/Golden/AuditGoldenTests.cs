using System;
using System.Collections.Generic;
using Capsara.SDK.Exceptions;
using Capsara.SDK.Models;
using FluentAssertions;
using Xunit;

namespace Capsara.SDK.Tests.Golden
{
    /// <summary>
    /// Golden tests for audit operations: request construction, validation, and action types.
    /// </summary>
    public class AuditGoldenTests
    {
        #region Request Construction Tests

        [Fact]
        public void CreateAuditEntryRequest_DefaultConstructor_SetsLogAction()
        {
            // Act
            var request = new CreateAuditEntryRequest();

            // Assert
            request.Action.Should().Be(AuditActions.Log);
            request.Details.Should().BeNull();
        }

        [Fact]
        public void CreateAuditEntryRequest_WithActionAndDetails_SetsCorrectly()
        {
            // Arrange
            var details = new Dictionary<string, object> { ["note"] = "Processed claim" };

            // Act
            var request = new CreateAuditEntryRequest(AuditActions.Processed, details);

            // Assert
            request.Action.Should().Be("processed");
            request.Details.Should().ContainKey("note");
            request.Details!["note"].Should().Be("Processed claim");
        }

        #endregion

        #region Action Types Tests

        [Fact]
        public void AuditActions_DefinesAllExpectedConstants()
        {
            // Assert
            AuditActions.Created.Should().Be("created");
            AuditActions.Accessed.Should().Be("accessed");
            AuditActions.FileDownloaded.Should().Be("file_downloaded");
            AuditActions.Processed.Should().Be("processed");
            AuditActions.Expired.Should().Be("expired");
            AuditActions.Deleted.Should().Be("deleted");
            AuditActions.Log.Should().Be("log");
        }

        #endregion

        #region Validation Tests

        [Fact]
        public void GetAuditEntriesFilters_DefaultValues()
        {
            // Act
            var filters = new GetAuditEntriesFilters();

            // Assert
            filters.Action.Should().BeNull();
            filters.Party.Should().BeNull();
            filters.Page.Should().BeNull();
            filters.Limit.Should().BeNull();
        }

        #endregion
    }
}
