/**
 * @license
 * Copyright Akveo. All Rights Reserved.
 * Licensed under the MIT License. See License.txt in the project root for license information.
 */
import { BrowserModule } from '@angular/platform-browser';
import { BrowserAnimationsModule } from '@angular/platform-browser/animations';
import { NgModule } from '@angular/core';
import { HttpClientModule,HttpResponse,HTTP_INTERCEPTORS } from '@angular/common/http';
import { CoreModule } from './@core/core.module';
import { ThemeModule } from './@theme/theme.module';
import { AppComponent } from './app.component';
import { AppRoutingModule } from './app-routing.module';
import { NgxAuthRoutingModule } from './auth/auth-routing.module';
import { NgxAuthModule } from './auth/auth.module';
import { JwtModule } from '@auth0/angular-jwt';
import { NbPasswordAuthStrategy, NbPasswordAuthStrategyOptions, NbAuthModule, NbAuthJWTToken } from '@nebular/auth';
import { AuthGuard } from './auth-guard.service';
import { MyInterceptor } from './interceptors/my.interceptor';
import { NgxUploaderModule } from 'ngx-uploader';

import {
  NbChatModule,
  NbDatepickerModule,
  NbDialogModule,
  NbMenuModule,
  NbSidebarModule,
  NbToastrModule,
  NbWindowModule,
  NbRouteTabsetModule,
} from '@nebular/theme';

@NgModule({
  declarations: [AppComponent],
  imports: [
    BrowserModule,
    BrowserAnimationsModule,
    HttpClientModule,
    AppRoutingModule,
    NgxAuthRoutingModule,
    NbSidebarModule.forRoot(),
    NbMenuModule.forRoot(),
    NbDatepickerModule.forRoot(),
    NbDialogModule.forRoot(),
    NbWindowModule.forRoot(),
    NbToastrModule.forRoot(),
    NbChatModule.forRoot({
      messageGoogleMapKey: 'AIzaSyA_wNuCzia92MAmdLRzmqitRGvCF7wCZPY',
    }),
    CoreModule.forRoot(),
    ThemeModule.forRoot(),
    NbRouteTabsetModule,
    NgxUploaderModule,
    NbAuthModule.forRoot({
      strategies: [
        NbPasswordAuthStrategy.setup({
          name: 'email',
          token: {
            class: NbAuthJWTToken,
            key: 'access',
            //getter: ( module: string,res: HttpResponse<Object>,options: NbPasswordAuthStrategyOptions) => {return res.headers.get('Authorization');},
          },
          baseEndpoint: 'http://185.230.211.59:8000/accounts',
          login: {
            endpoint: '/login',
            method: 'post',
          },

          register: {
            endpoint: '/sign-up',
            method: 'post',
          },
          logout: {
            endpoint: '/logout',
            method: 'post',

          },
          requestPass: {
            endpoint: '/request-pass',
          },
          resetPass: {
            endpoint: '/reset-pass',
          },
          //   redirect: {
          //      success: '/dashboard/', // welcome page path
          //      failure: null, // stay on the same page
          //    },
        }),
      ],
      forms: {},
    }),
  ],
  bootstrap: [AppComponent],
  providers: [
  //  CookieService,
    AuthGuard,
    { provide: HTTP_INTERCEPTORS, useClass: MyInterceptor, multi: true },
  ],
})
export class AppModule {
}
