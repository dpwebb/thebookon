'use strict';
const { createNotifications } = require('./core.cjs');
const specification = require('./templates.json');
function createProjectNotifications(overrides = {}) {
  const templates = Object.fromEntries(Object.entries(specification.templates).map(([event, item]) => [event, {
    ...item, text: input => item.message + '\nReference: ' + input.reference + (item.code && input.code ? '\nInvitation code: ' + input.code : '')
  }]));
  return createNotifications({ ...specification, templates, ...overrides });
}
const notifications = createProjectNotifications();
module.exports = { notifications, createProjectNotifications };
