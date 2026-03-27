-- Performance indexes for frequently queried tables
CREATE INDEX IF NOT EXISTS idx_learning_results_user_time ON learning_results(user_id, answered_at);
CREATE INDEX IF NOT EXISTS idx_learning_results_time ON learning_results(answered_at);
CREATE INDEX IF NOT EXISTS idx_ranking_stats_total_level ON ranking_stats(total_level DESC);
CREATE INDEX IF NOT EXISTS idx_ranking_stats_correct_count ON ranking_stats(correct_count DESC);
CREATE INDEX IF NOT EXISTS idx_class_members_user ON class_members(user_id);
CREATE INDEX IF NOT EXISTS idx_class_members_class ON class_members(class_id);
CREATE INDEX IF NOT EXISTS idx_rt_rooms_status ON rt_rooms(status, updated_at);
CREATE INDEX IF NOT EXISTS idx_rt_events_room ON rt_events(room_id, seq);
