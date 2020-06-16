import { CommonModule } from '@angular/common';
import { NgModule } from '@angular/core';
import { FormsModule } from '@angular/forms';
import { RouterModule } from '@angular/router';
import { NgxAuthComponent } from './auth.component';

import { NgxLoginComponent } from './login/login.component';
import { NbAuthModule } from '@nebular/auth';
import {
  NbAlertModule,
  NbButtonModule,
  NbCheckboxModule,
  NbInputModule,
  NbCardModule,
  NbLayoutModule,
  NbIconModule,
} from '@nebular/theme';
import { NbAuthComponent } from '@nebular/auth';  // <---

@NgModule({
  imports: [
    CommonModule,
    FormsModule,
    RouterModule,
    NbAlertModule,
    NbInputModule,
    NbButtonModule,
    NbCheckboxModule,
    NbCardModule,
    NbLayoutModule,
    NbAuthModule,
    NbIconModule,
  ],
  declarations: [
    NgxLoginComponent,
    NgxAuthComponent,
    // ... here goes our new components
  ],
})
export class NgxAuthModule {
}
