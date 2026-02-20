using System.Security.Cryptography;
using System.Text.Json;
using PSTParse;
using PSTParse.MessageLayer;

if (args.Length < 2)
{
    Console.Error.WriteLine("Usage: pstparse_extractor <pst_path> <out_dir>");
    return 2;
}

var pstPath = args[0];
var outDir = args[1];
Directory.CreateDirectory(outDir);

var result = new ExtractionResult();
var seenHashes = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
var sequence = 0;

try
{
    using var pst = new PSTFile(pstPath);
    WalkFolder(pst.TopOfPST);
}
catch (Exception ex)
{
    result.Errors.Add($"Fatal: {ex.Message}");
    Console.WriteLine(JsonSerializer.Serialize(result));
    return 1;
}

Console.WriteLine(JsonSerializer.Serialize(result));
return 0;

void WalkFolder(MailFolder folder)
{
    if (folder == null)
    {
        return;
    }

    try
    {
        foreach (var message in folder.GetIpmNotes() ?? Enumerable.Empty<Message>())
        {
            ProcessMessage(message);
        }
    }
    catch (Exception ex)
    {
        result.Errors.Add($"Folder '{folder.DisplayName}': {ex.Message}");
    }

    try
    {
        foreach (var subFolder in folder.SubFolders ?? new List<MailFolder>())
        {
            WalkFolder(subFolder);
        }
    }
    catch (Exception ex)
    {
        result.Errors.Add($"Subfolder traversal '{folder.DisplayName}': {ex.Message}");
    }
}

void ProcessMessage(Message message)
{
    if (message?.Attachments == null || !message.Attachments.Any())
    {
        return;
    }

    foreach (var attachment in message.Attachments)
    {
        try
        {
            var name = (attachment.AttachmentLongFileName ?? attachment.Filename ?? attachment.DisplayName ?? "").Trim();
            if (!LooksLikeDmarcAttachment(name))
            {
                continue;
            }

            var data = attachment.Data;
            if (data == null || data.Length == 0)
            {
                continue;
            }

            var digest = Convert.ToHexString(SHA256.HashData(data));
            if (!seenHashes.Add(digest))
            {
                continue;
            }

            sequence += 1;
            var ext = NormalizedExtension(name);
            var outputName = $"report_{sequence:D6}{ext}";
            var outputPath = Path.Combine(outDir, outputName);
            File.WriteAllBytes(outputPath, data);
            result.ExtractedFiles += 1;
        }
        catch (Exception ex)
        {
            result.Errors.Add($"Attachment processing failed: {ex.Message}");
        }
    }
}

bool LooksLikeDmarcAttachment(string filename)
{
    if (string.IsNullOrWhiteSpace(filename))
    {
        return false;
    }

    var lower = filename.ToLowerInvariant();
    return lower.EndsWith(".xml") || lower.EndsWith(".xml.gz") || lower.EndsWith(".gz");
}

string NormalizedExtension(string filename)
{
    if (string.IsNullOrWhiteSpace(filename))
    {
        return ".bin";
    }

    var lower = filename.ToLowerInvariant();
    if (lower.EndsWith(".xml.gz"))
    {
        return ".xml.gz";
    }

    if (lower.EndsWith(".xml"))
    {
        return ".xml";
    }

    if (lower.EndsWith(".gz"))
    {
        return ".gz";
    }

    return ".bin";
}

sealed class ExtractionResult
{
    public int ExtractedFiles { get; set; }

    public List<string> Errors { get; } = new();
}

