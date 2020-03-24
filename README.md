# Phân Quyền với Policy trong Laravel

## 1. Creating Policies

&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp; Policies  là các class tổ chức logic phân quyền xung quanh một  model hoặc resource cụ thể. Ví dụ: nếu ứng dụng của mình là blog, ta có thể có Post model và PostPolicy tương ứng để authorize cho các actions của user như create hoặc update các bài posts.

&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp; Ta có thể tạo policy bằng lệnh make:policy theo artisan command. Policy  được tạo sẽ được đặt trong thư mục app/Policies. Nếu thư mục này không tồn tại trong ứng dụng của bạn, Laravel sẽ tạo nó cho bạn:

```
php artisan make:policy PostPolicy
```

&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp; Lệnh **make:policy** sẽ tạo ra một empty policy class. Nếu ta muốn tạo một class với các **methods "CRUD"** policy cơ bản đã được bao gồm trong class, ta có thể chỉ định **--model** khi thực hiện lệnh:

```
php artisan make:policy PostPolicy --model=Post
```

## 1.1 Registering Policies

&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp; Một khi policy đã exists, nó cần phải được đăng ký. **AuthServiceProvider** đi kèm với các ứng dụng Laravel mới chứa policies property ánh xạ các Eloquent model của bạn tới các policy tương ứng của chúng. Đăng ký policy sẽ hướng dẫn cho Laravel sử dụng policy nào khi ủy quyền cho các actions  đối với một model nhất định:

```
<?php

namespace App\Providers;

use App\Policies\PostPolicy;
use App\Post;
use Illuminate\Foundation\Support\Providers\AuthServiceProvider as ServiceProvider;
use Illuminate\Support\Facades\Gate;

class AuthServiceProvider extends ServiceProvider
{
    /**
     * The policy mappings for the application.
     *
     * @var array
     */
    protected $policies = [
        Post::class => PostPolicy::class,
    ];

    /**
     * Register any application authentication / authorization services.
     *
     * @return void
     */
    public function boot()
    {
        $this->registerPolicies();

        //
    }
}
```

## 1.2 Policy Auto-Discovery

&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp; Thay vì đăng ký model policies theo cách thủ công, Laravel có thể **auto-discover** các policies miễn là model và policy tuân theo các quy ước đặt tên theo tiêu chuẩn của Laravel. Cụ thể, các policy phải nằm trong thư mục Policies bên dưới thư mục chứa các models. Vì vậy, ví dụ, các model có thể được đặt trong thư mục app trong khi các policy có thể được đặt trong thư mục app/Policies. Ngoài ra, tên policy phải khớp với tên model và có **Policy suffix**. Vì vậy, một User model sẽ tương ứng với một UserPolicy class.

&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp; Nếu bạn muốn cung cấp logic **discovery logic** của riêng mình, bạn có thể đăng ký một custom callback bằng phương thức **Gate::guessPolicyNamesUsing**. Thông thường, phương thức này phải được gọi từ method **boot** của AuthServiceProvider trong ứng dụng của bạn:

```
use Illuminate\Support\Facades\Gate;

Gate::guessPolicyNamesUsing(function ($modelClass) {
    // return policy class name...
});
```

## 2. Writing Policies

### 2.1. Policy Methods

&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp; Khi policy đã được registered, ta có thể thêm các methods  cho từng action được ủy quyền. Ví dụ: hãy define 1 update method trên PostPolicy của chúng ta để xác định xem một User cụ thể có thể update một phiên bản Post instance không.

&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp; Update method sẽ nhận được một User and a Post instance làm arguments của nó và sẽ return true or false cho biết user có được phép update Post đã cho hay không. Vì vậy, trong ví dụ này, hãy xác minh rằng id của người dùng khớp với user_id trên bài post:

```
<?php

namespace App\Policies;

use App\Post;
use App\User;

class PostPolicy
{
    /**
     * Determine if the given post can be updated by the user.
     *
     * @param  \App\User  $user
     * @param  \App\Post  $post
     * @return bool
     */
    public function update(User $user, Post $post)
    {
        return $user->id === $post->user_id;
    }
}
```

### 2.2. Policy Responses

&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp; Cho đến giờ, chúng ta chỉ kiểm tra các policy methods mà return các giá trị boolean đơn giản. Tuy nhiên, đôi khi bạn có thể muốn trả lại response chi tiết hơn, bao gồm **error message**. Để làm như vậy, ta có thể trả về **Illuminate\Auth\Access\Response** từ policy method của mình:

```
use Illuminate\Auth\Access\Response;

/**
 * Determine if the given post can be updated by the user.
 *
 * @param  \App\User  $user
 * @param  \App\Post  $post
 * @return \Illuminate\Auth\Access\Response
 */
public function update(User $user, Post $post)
{
    return $user->id === $post->user_id
                ? Response::allow()
                : Response::deny('You do not own this post.');
}
```

&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp; Khi return **authorization response** từ policy của bạn, method  **Gate::allow** vẫn sẽ return giá trị boolean đơn giản; tuy nhiên, ta có thể sử dụng method **Gate::tests** để nhận được **authorization response** đầy đủ mà gate trả về:

```
$response = Gate::inspect('update', $post);

if ($response->allowed()) {
    // The action is authorized...
} else {
    echo $response->message();
}
```

&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp; Tất nhiên, khi sử dụng method **Gate::authorize** để throw **AuthorizationException** nếu action không được authorized, **error message** được cung cấp bởi **authorization response** sẽ được truyền đến **HTTP response**:

```
Gate::authorize('update', $post);

// The action is authorized...
```

### 2.3. Methods Without Models

&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp; Một số policy methods chỉ nhận **currently authenticated user** và không phải là instance của model mà nó authorize. Tình huống này rất phổ biến nhất là khi authorizing **create actions**. Ví dụ: nếu bạn đang tạo một blog, bạn có thể muốn kiểm tra xem user có được phép tạo bất kỳ bài posts nào không.

&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp; Khi định nghĩa các policy methods mà không nhận được một model instance, chẳng hạn như một **create method**, nó sẽ không nhận được một model instance. Thay vào đó, bạn nên định nghĩa method là chỉ **expecting authenticated user**:

```
/**
 * Determine if the given user can create posts.
 *
 * @param  \App\User  $user
 * @return bool
 */
public function create(User $user)
{
    //
}
```

### 2.4. Guest Users

&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp; Mặc định, tất cả các gates và policies sẽ tự động trả về false nếu incoming HTTP request không được initiated bởi authenticated user. Tuy nhiên, ta có thể cho phép các **authorization checks** này chuyển qua gates và policies của mình bằng cách declaring **"optional" type-hint** hoặc cung cấp **null default value** cho định nghĩa user argument:

```
<?php

namespace App\Policies;

use App\Post;
use App\User;

class PostPolicy
{
    /**
     * Determine if the given post can be updated by the user.
     *
     * @param  \App\User  $user
     * @param  \App\Post  $post
     * @return bool
     */
    public function update(?User $user, Post $post)
    {
        return optional($user)->id === $post->user_id;
    }
}
```

### 2.5. Policy Filters

&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp; Đối với một số users nhất định, ta có thể muốn ủy quyền tất cả các actions trong một policy nhất định. Để thực hiện điều này, hãy định nghĩa một **before method** trong policy. Method before sẽ được thực thi trước bất kỳ method nào khác trong policy, cho ta cơ hội authorize  action trước khi phương thức policy dự định thực sự được gọi. Tính năng này được sử dụng rất phổ biến nhất để authorizing cho application administrators thực hiện bất kỳ hành động nào:

```
public function before($user, $ability)
{
    if ($user->isSuperAdmin()) {
        return true;
    }
}
```

&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp; Nếu bạn muốn deny tất cả các authorizations cho một user, bạn nên return false từ method before. Nếu null được return, authorization sẽ rơi vào policy method.

# 3. Practise

&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp; Giả sử ta có bài toán muốn phân quyền trong trang Admin để chỉ có superadmin có quyền xem mục Purchase trên thanh sidebar (nơi hiển thị lịch sử mua vé của user) - Purchase Model:

&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp; Đầu tiên ta tạo 1 class Policy

```
php artisan make:policy PurchasePolicy --model=Purchase
```
Sau đó ta đăng kí Policy này trong app/Providers/AuthServiceProvider.php

```
protected $policies = [
    Purchase::class => PurchasePolicy::class,
];
```

&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp; Trong PurchasePolicy ta có thể sử dụng hàm **viewAny** để check xem đây có phải user super admin, đây là 1 hàm mới Laravel tự generate khi ta chạy tạo policy với --model
```
    /**
     * Determine whether the user can view any purchases.
     *
     * @param  \App\Models\User  $user
     * @return mixed
     */
    public function viewAny(User $user)
    {
        return $user->role == config('user.role.super_admin');
    }
```

&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp; Giải thích: Trong bảng user ta đơn giản đặt 1 trường role có kiểu int, sau đó định nghĩa các role này trong file config

```
<?php

return [
    'role' => [
        'super_admin' => 1,
        'total_location' => 2,
        'location' => 3,
    ]
];
```

&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp; Ở trên ta đang muốn check chỉ có super admin mới xem được mục Purchase trên sidebar, các user khác ko xem được mục này

&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp; Trong blade ta đơn giản check **can** là xong:

```
@can('viewAny', App\Models\Purchase::class)
    <ul class="nav nav-pills nav-sidebar flex-column text-sm nav-child-indent" data-widget="treeview" role="menu">
        <li class="nav-item">
            <a class="nav-link href="{{ route('admin.purchase-history') }}">
                <i class="nav-icon fas fa-shopping-cart"></i>
                <span class="brand-text">{{ __('admin.side_bar.purchase_history') }}</span>
            </a>
        </li>
    </ul>
@endcan
```

Tất nhiên là ta cũng sẽ phải phân quyền để làm sao chỉ có super_admin mới truy cập được route('admin.purchase-history') ta có thể dùng 1 trong 2 cách như sau tuy mọi người lựa chọn:

&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp; Dùng **middleware trong route**: cách này mình thấy rất hay, rất gọn gàng mình có thể nhìn thấy ngay midleware trong route mà ko còn phải  mò vào controller để tìm kiếm, tuy nhiên một số bạn thì ko thích cách này lắm do code hơi dài dòng nhìn nó xấu. Tùy quan điểm cá nhân mỗi người ạ :)))

Route::group(['namespace' => 'Admin', 'as' => 'admin.', 'middleware' => ['web', 'auth']], function () {
    //
    Route::get('purchase-history', 'StatisticController@getPurchasedHistory')->name('purchase-history')->middleware('can:viewAny,App\Models\Purchase');
    //
});


&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp; Mình thấy đa số mọi người hay dùng cách thứ 2 là **authorized trong controller** như sau:

```
<?php

namespace App\Http\Controllers\Admin;

...

class StatisticController extends BaseController
{
    ...
    
    public function getPurchasedHistory(PurchasedHistoryRequest $request)
    {
        $this->authorize('viewAny', Purchase::class);
        
        // The current user can view purchase...
    }
    
    ...
}
```

Ok vậy xong rồi, việc phân quyền chỉ đơn giản vậy thôi Laravel đã hỗ trợ cho mình sẵn rồi, các bạn có thể thiết kế nhiều cách phân quyền khác nữa ngoài cách gán trường role vào bảng user như mình nhé :D

Tài liệu tham khảo: [https://laravel.com/docs/6.x/authorization](https://laravel.com/docs/6.x/authorization)
