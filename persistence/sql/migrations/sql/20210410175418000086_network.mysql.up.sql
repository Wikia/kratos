ALTER TABLE `sessions` ADD CONSTRAINT `sessions_nid_fk_idx` FOREIGN KEY (`nid`) REFERENCES `networks` (`id`) ON UPDATE RESTRICT ON DELETE CASCADE;