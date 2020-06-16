import { NgModule } from '@angular/core';
import { MatIconModule } from '@angular/material/icon';

import {
  NbActionsModule,
  NbButtonModule,
  NbCardModule,
  NbTabsetModule,
  NbUserModule,
  NbRadioModule,
  NbSelectModule,
  NbListModule,
  NbIconModule,
  NbSidebarModule,
  NbLayoutModule,
  NbContextMenuModule,
  NbMenuModule,

} from '@nebular/theme';
import { ThemeModule } from '../../@theme/theme.module';
import { TopAppInfoComponent } from './top-app-info.component';
import { NgxChartsModule } from '@swimlane/ngx-charts';

@NgModule({
  imports: [
    ThemeModule,
    NbSidebarModule,
    NbContextMenuModule,
    NbLayoutModule,
    MatIconModule,
    NgxChartsModule,
    NbCardModule,
    NbMenuModule,


  ],
  exports: [
    TopAppInfoComponent,
  ],
  declarations: [
    TopAppInfoComponent,

  ],
})
export class TopAppInfoModule {
}
