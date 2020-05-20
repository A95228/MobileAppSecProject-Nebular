/*global gettext, interpolate, ngettext*/
(function($) {
    'use strict';
    var lastChecked;
    $(document).ready(function(){
      if( $(".user_permissions").length ){
        var html = '<div class="form-row grp-row grp-cells-1 user_presets ">'+
                      '<div class="field-box l-2c-fluid l-d-4">'+
                        '<div class="c-1">'+
                          '<label for="id_user_presets">User Presets</label>'+
                        '</div>'+
                        '<div class="c-2">'+
                          '<div class="grp-related-widget-wrapper related-widget-wrapper">'+
                            '<div class="grp-related-widget">'+
                              '<div class="selector">'+
                                '<div class="selector-available">'+
                                  '<h2>Available presets <span class="help help-tooltip help-icon" title="This is the list of presets."></span></h2>'+
                                  '<select name="user_presets_old" id="id_user_presets_from data-is-stacked="0">'+
                                    '<option value="1">Super Admin</option>'+
                                    '<option value="2">Admin</option>'+
                                    '<option value="3">Security Analyst</option>'+
                                    '<option value="4">Developer</option>'+
                                    '<option value="5">Compliance Officer/Auditor</option>'+
                                    '<option value="5">Manager</option>'+
                                  '</select>'+
                                '</div>'+
                              '</div>'+
                            '</div>'+
                          '</div>'+
                          '<p class="grp-help"></p>'+
                        '</div>'+
                      '</div>'+
                  '</div>';
        $(".user_permissions").after(html);
      }
    });
})(grp.jQuery);
