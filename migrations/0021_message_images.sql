-- Add image column to messages table for chat image attachments
-- Images are stored as base64 data URIs (JPEG, compressed to ~60% quality, max 800px width)
-- Images older than 14 days are automatically cleaned up (set to NULL) to save storage

ALTER TABLE messages ADD COLUMN image TEXT;
