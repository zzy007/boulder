
-- +goose Up
-- SQL in section 'Up' is executed when this migration is applied

ALTER TABLE `registrations` ADD COLUMN (`status` varchar(255) DEFAULT "valid" NOT NULL);

-- +goose Down
-- SQL section 'Down' is executed when this migration is rolled back

ALTER TABLE `registrations` DROP COLUMN `status`;
