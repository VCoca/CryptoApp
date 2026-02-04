using System.Text.Json;

namespace CryptoApp.Core.File
{
    internal class MetadataHeader
    {
        public string name { get; set; }
        public long size { get; set; }
        public DateTime createdAt { get; set; }
        public string encryption { get; set; }
        public string hash { get; set; }
        public MetadataHeader(string name, long size, DateTime createdAt, string encryption, string hash)
        {
            this.name = name;
            this.size = size;
            this.createdAt = createdAt;
            this.encryption = encryption;
            this.hash = hash;
        }
        public string ToJson()
        {
            return JsonSerializer.Serialize(this);
        }
        public static MetadataHeader FromJson(string json)
        {
            return JsonSerializer.Deserialize<MetadataHeader>(json)
                ?? throw new InvalidOperationException("Failed to deserialize MetadataHeader from JSON.");
        }
    }
}
