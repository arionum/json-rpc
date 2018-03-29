
--
-- Table structure for table `wallets`
--

CREATE TABLE `wallets` (
  `id` int(11) NOT NULL,
  `address` varchar(256) COLLATE utf8mb4_bin NOT NULL,
  `public_key` varchar(760) COLLATE utf8mb4_bin NOT NULL,
  `private_key` varchar(760) COLLATE utf8mb4_bin NOT NULL,
  `data` int(11) NOT NULL DEFAULT 0,
  `acc` varchar(120) COLLATE utf8mb4_bin NOT NULL DEFAULT '0'
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_bin;


--
-- Table structure for table `wallet_config`
--

CREATE TABLE `wallet_config` (
  `id` varchar(32) COLLATE utf8mb4_bin NOT NULL,
  `val` text COLLATE utf8mb4_bin NOT NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_bin;

--
-- Dumping data for table `wallet_config`
--

INSERT INTO `wallet_config` (`id`, `val`) VALUES
('expiry', '0'),
('iv', ''),
('private_key', ''),
('public_key', '');

--
-- Indexes for dumped tables
--

--
-- Indexes for table `wallets`
--
ALTER TABLE `wallets`
  ADD PRIMARY KEY (`id`),
  ADD KEY `acc` (`acc`);

--
-- Indexes for table `wallet_config`
--
ALTER TABLE `wallet_config`
  ADD PRIMARY KEY (`id`);

--
-- AUTO_INCREMENT for dumped tables
--

--
-- AUTO_INCREMENT for table `wallets`
--
ALTER TABLE `wallets`
  MODIFY `id` int(11) NOT NULL AUTO_INCREMENT, AUTO_INCREMENT=17;
COMMIT;

