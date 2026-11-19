//! The scene laye's login is drawn on: bevy-starter's bowl and its one light,
//! under bevy-starter's camera.
//!
//! Nothing here is pressed or steered. The camera turns slowly around the
//! bowl and the light breathes. When the page says who you are, through
//! `known`, the light turns into ground.institute's symbol, IEC 5019, and
//! locks into place facing you.

// "right, and its a clean and seamless experience"
// "different from the QNTX fractal door"
// "laye is calm"

// "i have an idea, lets just use the ground institute unicode symbol as symbol of laye, but, its the sphere turning into it in 3d and locking into place, as to signnify,"
// "you are connected to laye"

use std::sync::atomic::{AtomicBool, Ordering};

use bevy::camera::Hdr;
use bevy::post_process::bloom::Bloom;
use bevy::prelude::*;
use bevy::window::WindowPlugin;

#[cfg(target_arch = "wasm32")]
use wasm_bindgen::prelude::*;

/// bevy-starter's camera: above and behind what it looks at.
const CAMERA_OFFSET: Vec3 = Vec3::new(0.0, 12.0, 16.0);
/// Where the camera looks: below the bowl, so the bowl and the light stand in
/// the upper half of a phone, above the panel.
const LOOK_AT: Vec3 = Vec3::new(0.0, -4.0, 0.0);
/// One turn around the bowl, in seconds.
const TURN: f32 = 240.0;
/// One breath of the light, in seconds.
const BREATH: f32 = 7.0;

/// How long the light takes to become the symbol, in seconds.
const BECOMING: f32 = 2.4;
/// Turns the symbol makes before it locks.
const SPINS: f32 = 2.0;
/// Where the symbol stands: above the bowl, where the light was.
const SYMBOL_AT: Vec3 = Vec3::new(0.0, 1.8, 0.0);

/// What the light is before laye knows you, and after.
const STRANGER: Vec3 = Vec3::new(0.8, 1.4, 2.0);
const KNOWN_LIGHT: Vec3 = Vec3::new(2.0, 1.1, 0.9);

static KNOWN: AtomicBool = AtomicBool::new(false);

/// The page tells the scene laye knows who is holding it.
#[cfg_attr(target_arch = "wasm32", wasm_bindgen)]
pub fn known(yes: bool) {
    KNOWN.store(yes, Ordering::Relaxed);
}

#[derive(Component)]
struct Light;

#[derive(Resource)]
struct LightMaterial(Handle<StandardMaterial>);

/// IEC 5019, protective earth: the ground mark in a circle.
#[derive(Component)]
struct Symbol;

/// One stroke of the symbol, and where it rests once locked.
#[derive(Component)]
struct Stroke(Transform);

/// How far the light has become the symbol, 0 to 1.
#[derive(Resource, Default)]
struct Becoming(f32);

#[cfg_attr(target_arch = "wasm32", wasm_bindgen(start))]
pub fn run() {
    App::new()
        .insert_resource(ClearColor(Color::srgb(0.01, 0.02, 0.05)))
        .add_plugins(DefaultPlugins.set(WindowPlugin {
            primary_window: Some(Window {
                title: "laye".to_string(),
                canvas: Some("#scene".to_owned()),
                fit_canvas_to_parent: true,
                prevent_default_event_handling: false,
                ..default()
            }),
            ..default()
        }))
        .add_systems(Startup, setup)
        .init_resource::<Becoming>()
        .add_systems(
            Update,
            (
                turn,
                breathe,
                become_symbol,
                give_light,
                lock_symbol,
                draw_strokes,
            )
                .chain(),
        )
        .run();
}

fn setup(
    mut commands: Commands,
    mut meshes: ResMut<Assets<Mesh>>,
    mut materials: ResMut<Assets<StandardMaterial>>,
) {
    commands.spawn((
        Camera3d::default(),
        Hdr,
        Bloom::default(),
        Transform::from_translation(CAMERA_OFFSET).looking_at(LOOK_AT, Vec3::Y),
    ));
    commands.spawn((
        DirectionalLight {
            illuminance: 2000.0,
            color: Color::srgb(0.6, 0.65, 0.8),
            shadow_maps_enabled: false,
            ..default()
        },
        Transform::from_xyz(8.0, 20.0, 8.0).looking_at(Vec3::ZERO, Vec3::Y),
    ));
    commands.spawn((
        Mesh3d(meshes.add(Cylinder::new(8.0, 0.4))),
        MeshMaterial3d(materials.add(StandardMaterial {
            base_color: Color::srgb(0.15, 0.18, 0.25),
            perceptual_roughness: 0.9,
            metallic: 0.0,
            ..default()
        })),
        Transform::from_xyz(0.0, -0.2, 0.0),
    ));
    let light = materials.add(StandardMaterial {
        base_color: Color::srgb(0.6, 0.9, 1.0),
        emissive: LinearRgba::rgb(STRANGER.x, STRANGER.y, STRANGER.z),
        ..default()
    });
    commands.insert_resource(LightMaterial(light.clone()));
    commands.spawn((
        Light,
        Mesh3d(meshes.add(Sphere::new(0.6))),
        MeshMaterial3d(light.clone()),
        Transform::from_xyz(0.0, 0.6, 0.0),
    ));

    // The strokes, in the symbol's own plane (x across, y up), the light's
    // material on every one of them.
    let mut bar = |width: f32| meshes.add(Cuboid::new(width, 0.14, 0.14));
    let bars = [bar(1.3), bar(0.86), bar(0.42)];
    let strokes = [
        (
            meshes.add(Torus::new(1.26, 1.4)),
            Transform::from_rotation(Quat::from_rotation_x(std::f32::consts::FRAC_PI_2)),
        ),
        (
            meshes.add(Cuboid::new(0.14, 0.75, 0.14)),
            Transform::from_xyz(0.0, 0.42, 0.0),
        ),
    ]
    .into_iter()
    .chain(
        bars.into_iter()
            .zip([0.05, -0.3, -0.65])
            .map(|(b, y)| (b, Transform::from_xyz(0.0, y, 0.0))),
    );
    commands
        .spawn((
            Symbol,
            Transform::from_translation(Vec3::new(0.0, 0.6, 0.0)),
            Visibility::Hidden,
        ))
        .with_children(|symbol| {
            for (mesh, rest) in strokes {
                symbol.spawn((
                    Stroke(rest),
                    Mesh3d(mesh),
                    MeshMaterial3d(light.clone()),
                    Transform::from_scale(Vec3::ZERO),
                ));
            }
        });
}

/// Eases out past its end and settles back: the lock.
fn settle(t: f32) -> f32 {
    let c = 1.4;
    let u = t - 1.0;
    1.0 + (c + 1.0) * u * u * u + c * u * u
}

/// The light becomes the symbol while laye knows you, and the symbol the light
/// again when it no longer does.
fn become_symbol(time: Res<Time>, mut becoming: ResMut<Becoming>) {
    let step = time.delta_secs() / BECOMING;
    becoming.0 = if KNOWN.load(Ordering::Relaxed) {
        (becoming.0 + step).min(1.0)
    } else {
        (becoming.0 - step).max(0.0)
    };
}

/// The light gives itself to the symbol in the first half.
fn give_light(becoming: Res<Becoming>, mut lights: Query<&mut Transform, With<Light>>) {
    for mut light in &mut lights {
        light.scale = Vec3::splat((1.0 - becoming.0 * 2.0).max(0.0));
    }
}

/// The symbol rises where the light was, turning, and locks facing you.
fn lock_symbol(
    becoming: Res<Becoming>,
    cameras: Query<&Transform, (With<Camera3d>, Without<Symbol>)>,
    mut symbols: Query<(&mut Transform, &mut Visibility), With<Symbol>>,
) {
    let t = becoming.0;
    let Ok(camera) = cameras.single() else { return };
    for (mut symbol, mut visibility) in &mut symbols {
        *visibility = if t > 0.0 {
            Visibility::Inherited
        } else {
            Visibility::Hidden
        };
        symbol.translation = Vec3::new(0.0, 0.6, 0.0).lerp(SYMBOL_AT, settle(t));
        // Its face toward the camera, whole: the camera stands above it.
        let away = symbol.translation * 2.0 - camera.translation;
        let facing = symbol.looking_at(away, Vec3::Y).rotation;
        let spin = (1.0 - t) * (1.0 - t) * SPINS * std::f32::consts::TAU;
        symbol.rotation = facing * Quat::from_rotation_y(spin);
    }
}

/// Each stroke grows from the light's centre to where it rests.
fn draw_strokes(becoming: Res<Becoming>, mut strokes: Query<(&Stroke, &mut Transform)>) {
    let shown = settle(becoming.0);
    for (stroke, mut transform) in &mut strokes {
        transform.translation = stroke.0.translation * shown;
        transform.rotation = stroke.0.rotation;
        transform.scale = Vec3::splat(shown.max(0.0));
    }
}

fn turn(time: Res<Time>, mut cameras: Query<&mut Transform, With<Camera3d>>) {
    let angle = time.elapsed_secs() * std::f32::consts::TAU / TURN;
    let around = Quat::from_rotation_y(angle) * CAMERA_OFFSET;
    for mut camera in &mut cameras {
        camera.translation = around;
        camera.look_at(LOOK_AT, Vec3::Y);
    }
}

fn breathe(
    time: Res<Time>,
    held: Res<LightMaterial>,
    mut materials: ResMut<Assets<StandardMaterial>>,
    mut toward: Local<f32>,
) {
    let target = if KNOWN.load(Ordering::Relaxed) {
        1.0
    } else {
        0.0
    };
    *toward += (target - *toward) * (time.delta_secs() * 0.8).min(1.0);
    let breath = 0.85 + 0.15 * (time.elapsed_secs() * std::f32::consts::TAU / BREATH).sin();
    let glow = STRANGER.lerp(KNOWN_LIGHT, *toward) * breath;
    if let Some(mut material) = materials.get_mut(&held.0) {
        material.emissive = LinearRgba::rgb(glow.x, glow.y, glow.z);
    }
}
