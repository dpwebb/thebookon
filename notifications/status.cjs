'use strict';
const {notifications}=require('./project.cjs');
try{console.log(JSON.stringify(notifications.health()));}finally{notifications.close();}
