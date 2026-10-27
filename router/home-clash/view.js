'use strict';
'require view';
'require fs';
'require ui';
return view.extend({
 load: function() {
  return fs.exec('/usr/sbin/home-clash', ['status']).then(function(r) { try { return JSON.parse(r.stdout); } catch(e) { return {}; } });
 },
 render: function(data) {
  var link=E('input', {type:'password', class:'cbi-input-text', autocomplete:'off', placeholder:'https://…', style:'max-width:650px;width:100%'});
  var state=E('p', {}, data.ok ? ('Mihomo · '+data.rules+' правил · обновлено '+(data.updated ? new Date(data.updated).toLocaleString('ru-RU') : 'сейчас')) : 'Состояние временно недоступно');
  function invoke(args) {
   ui.showModal('Применение подписки', [E('p', {class:'spinning'}, 'Загрузка и проверка. При ошибке сохранится прежний конфиг.')]);
   return fs.exec('/usr/sbin/home-clash',args).then(function(r) {
    ui.hideModal();var result;try{result=JSON.parse(r.stdout);}catch(e){result={ok:false};}
    if(r.code!==0||!result.ok){ui.addNotification(null,E('p',{},'Не удалось применить. Прежняя конфигурация сохранена.'),'error');return;}
    window.location.reload();
   }).catch(function(){ui.hideModal();ui.addNotification(null,E('p',{},'Проверьте статус обновления перед повторной попыткой.'),'error');});
  }
  var rows=[E('h2',{},'Подписка Clash'),state,E('p',{},'Прокси и сетевые правила берутся из подписки, включая DIRECT. Правила по именам приложений домашних устройств роутер применить не может.'),E('p',{},'Новая ссылка подписки (необязательно):'),link,E('div',{class:'cbi-page-actions'},[
   E('button',{class:'cbi-button cbi-button-apply',click:function(){var value=link.value.trim();if(value){if(!value.startsWith('https://')){ui.addNotification(null,E('p',{},'Нужна ссылка HTTPS.'),'error');return;}return fs.write('/etc/home-clash/private/new-url',value+'\n',384).then(function(){link.value='';return invoke(['import']);});}return invoke(['update']);}},'Импортировать / обновить')
  ])];
  (data.groups||[]).forEach(function(g){
   var select=E('select',{class:'cbi-input-select'},g.options.map(function(n){return E('option',{value:n,selected:n===g.selected?'selected':null},n);}));
   rows.push(E('div',{class:'cbi-section'},[E('h3',{},g.name),select,E('button',{class:'cbi-button cbi-button-action',style:'margin-left:12px',click:function(){return invoke(['select',g.name,select.value]);}},'Выбрать')]));
  });
  rows.push(E('p',{},'Автообновление: 01:17, 07:17, 13:17 и 19:17. Доступность каждого прокси зависит от провайдера подписки.'));
  return E('div',{},rows);
 },
 handleSaveApply:null,handleSave:null,handleReset:null
});
