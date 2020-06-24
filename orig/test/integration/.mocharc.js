
module.exports = {
    recursive: true,
    extension: ['js'],
    diff: true,
    opts: false,
    exit: true,
    reporter: 'spec',
    slow: 75,
    timeout: 2000,
    ui: 'bdd',
    spec: 'test/integration/**/*.test.js'
};
