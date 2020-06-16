import { NgModule } from '@angular/core';
import { ThemeModule } from '../../@theme/theme.module';
import { ApiComponent } from './api.component';
import { MatTableModule } from '@angular/material/table';

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
} from '@nebular/theme';

@NgModule({
  imports: [
    ThemeModule,
    NbCardModule,
    NbTabsetModule,
    MatTableModule,
  ],
  declarations: [
    ApiComponent,
  ],
  providers: [
  ]
})
export class ApiModule {
}
