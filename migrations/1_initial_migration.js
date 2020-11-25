const Migrations = artifacts.require("Migrations");

module.exports = function(deployer, network) {
  if (network === 'development') {
    deployer.deploy(Migrations);
  }
};
